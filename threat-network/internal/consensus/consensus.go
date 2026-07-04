// Package consensus runs the windowed aggregation, promotion, and decay job.
// It implements the simplified core of research/deep-dive-consensus-algorithm.md
// per specs/003-threat-network/plan.md: all reporters weigh 1.0, thresholds do
// the anti-poisoning work, a single reporter can never promote an indicator.
package consensus

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/ingest"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// Window is the trailing aggregation window (7 days per plan.md).
const Window = 7 * 24 * time.Hour

// ReporterMaturationDelay is how long a newly registered reporter_id must age
// before it counts toward promotion distinctness thresholds. Registration mints
// unlimited independent reporter_ids with no operator identity, so the distinct-
// reporter count alone is Sybil-forgeable: one actor can register several ids and
// send the identical signal from each to force a promotion. Requiring each id to
// pre-date the run by this delay means a Sybil cluster cannot promote on demand —
// the attacker must sustain the ids for at least this long, and a
// registration-velocity burst is detectable/deniable within it. See finding #1
// and specs/003-threat-network FR-5 (a single reporter can never cause promotion).
const ReporterMaturationDelay = 24 * time.Hour

// Engine owns a consensus run against the store.
type Engine struct {
	DB  *store.DB
	Now func() time.Time
}

// New builds an Engine with real time.
func New(db *store.DB) *Engine {
	return &Engine{DB: db, Now: time.Now}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// aggregate is the reduced per-indicator view over the window.
type aggregate struct {
	kind          string
	indicatorKey  string
	indicator     string
	isExactDomain bool
	etldPlusOne   string // for allowlist guard
	// per-reporter max confidence (influence cap: each reporter counts once)
	perReporter map[string]float64
	totalObs    int
	reasons     map[string]bool
	hasKnownBad bool
	firstSeen   time.Time
	lastSeen    time.Time
}

// Run executes one full consensus pass: aggregate → promote → decay. It is
// idempotent (recomputes from signals) so a crash mid-run heals on the next run.
func (e *Engine) Run() error {
	now := e.now()
	since := now.Add(-Window)

	deny, err := e.DB.DenylistedReporterIDs()
	if err != nil {
		return err
	}
	signals, err := e.DB.SignalsInWindow(since, deny)
	if err != nil {
		return err
	}

	// Sybil defense: only reporter_ids that have aged past the maturation delay
	// count toward promotion distinctness. Freshly-registered ids still have their
	// signals aggregated (for observability), but do not move an indicator toward
	// the wire.
	mature, err := e.DB.MatureReporterIDs(now.Add(-ReporterMaturationDelay))
	if err != nil {
		return err
	}

	aggs := buildAggregates(signals)

	// Persist aggregates + evaluate promotion.
	promoted := map[string]bool{} // key: kind|indicator
	for _, ag := range aggs {
		// Observed distinct/confidence over ALL non-denylisted reporters (recorded
		// on the aggregate for observability).
		distinct := len(ag.perReporter)
		avgConf := meanConfidence(ag.perReporter)

		// Promotion distinct/confidence over MATURE reporters only (Sybil defense):
		// immature reporter_ids do not count toward thresholds.
		matureReporter := filterMature(ag.perReporter, mature)
		promoteDistinct := len(matureReporter)
		promoteConf := meanConfidence(matureReporter)

		reasons := sortedKeys(ag.reasons)
		reasonsJSON, _ := json.Marshal(reasons)

		if err := e.DB.UpsertAggregate(store.AggregateRow{
			Kind:                ag.kind,
			IndicatorKey:        ag.indicatorKey,
			DistinctReporters:   distinct,
			AggregateConfidence: avgConf,
			TotalObservations:   ag.totalObs,
			Reasons:             string(reasonsJSON),
			HasKnownBad:         ag.hasKnownBad,
			FirstSeen:           ag.firstSeen.UTC().Format(time.RFC3339),
			LastSeen:            ag.lastSeen.UTC().Format(time.RFC3339),
			ComputedAt:          now.UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}

		// Allowlist guard: popular eTLD+1 is never promoted; flag the reporters.
		if ag.etldPlusOne != "" {
			allowed, err := e.DB.IsAllowlisted(ag.etldPlusOne)
			if err != nil {
				return err
			}
			if allowed {
				day := now.UTC().Format("2006-01-02")
				for rid := range ag.perReporter {
					_ = e.DB.AddCounters(rid, day, 0, 0, 0, 1)
				}
				continue
			}
		}

		decision := evaluate(ag, promoteDistinct, promoteConf)
		if !decision.promote {
			continue
		}

		conf := feedConfidence(promoteConf, promoteDistinct)
		if err := e.upsertFeedItem(now, ag, decision, conf, promoteDistinct, reasons); err != nil {
			return err
		}
		promoted[ag.kind+"|"+ag.indicator] = true
	}

	// Decay/lifecycle: refresh or revoke existing feed items.
	if err := e.applyLifecycle(now); err != nil {
		return err
	}
	return nil
}

// buildAggregates reduces raw signals into per-(kind, indicator) aggregates,
// applying the per-reporter influence cap (max confidence, counted once).
func buildAggregates(signals []store.SignalRow) []*aggregate {
	byKey := map[string]*aggregate{}
	for _, s := range signals {
		key := s.Kind + "|" + s.IndicatorKey
		ag := byKey[key]
		if ag == nil {
			ag = &aggregate{
				kind:         s.Kind,
				indicatorKey: s.IndicatorKey,
				indicator:    indicatorString(s),
				perReporter:  map[string]float64{},
				reasons:      map[string]bool{},
			}
			ag.isExactDomain = s.Kind == ingest.KindKnownBad
			ag.etldPlusOne = etldForGuard(s)
			byKey[key] = ag
		}
		if c, ok := ag.perReporter[s.ReporterID]; !ok || s.LocalConfidence > c {
			ag.perReporter[s.ReporterID] = s.LocalConfidence
		}
		ag.totalObs += s.ObservationCount
		for _, r := range decodeReasons(s.LocalReasons) {
			ag.reasons[r] = true
			if r == "known_bad" {
				ag.hasKnownBad = true
			}
		}
		bucket := parseTime(s.TimeBucket)
		if ag.firstSeen.IsZero() || bucket.Before(ag.firstSeen) {
			ag.firstSeen = bucket
		}
		if bucket.After(ag.lastSeen) {
			ag.lastSeen = bucket
		}
	}
	out := make([]*aggregate, 0, len(byKey))
	for _, ag := range byKey {
		out = append(out, ag)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].kind+out[i].indicatorKey < out[j].kind+out[j].indicatorKey
	})
	return out
}

func indicatorString(s store.SignalRow) string {
	switch s.Kind {
	case ingest.KindKnownBad:
		return s.Domain
	case ingest.KindCandidate:
		return s.EtldPlusOne
	default:
		return s.Behavior
	}
}

// etldForGuard returns the eTLD+1 to check against the allowlist, or "" for
// behavior clusters (which have no domain material).
func etldForGuard(s store.SignalRow) string {
	switch s.Kind {
	case ingest.KindKnownBad:
		return s.EtldPlusOne
	case ingest.KindCandidate:
		return s.EtldPlusOne
	default:
		return ""
	}
}

// filterMature returns the subset of perReporter whose ids are in the mature set.
// Only these count toward promotion thresholds (Sybil defense, finding #1).
func filterMature(perReporter map[string]float64, mature map[string]bool) map[string]float64 {
	out := make(map[string]float64, len(perReporter))
	for id, conf := range perReporter {
		if mature[id] {
			out[id] = conf
		}
	}
	return out
}

func meanConfidence(perReporter map[string]float64) float64 {
	if len(perReporter) == 0 {
		return 0
	}
	var sum float64
	for _, c := range perReporter {
		sum += c
	}
	return sum / float64(len(perReporter))
}

// feedConfidence = min(0.99, avg_conf * (0.7 + 0.3 * min(1, distinct/5))).
func feedConfidence(avgConf float64, distinct int) float64 {
	factor := float64(distinct) / 5.0
	if factor > 1 {
		factor = 1
	}
	c := avgConf * (0.7 + 0.3*factor)
	if c > 0.99 {
		c = 0.99
	}
	return c
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func decodeReasons(j string) []string {
	var out []string
	_ = json.Unmarshal([]byte(j), &out)
	return out
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t.UTC()
}
