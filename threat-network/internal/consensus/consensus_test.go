package consensus

import (
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/ingest"
	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func readerString(s string) *strings.Reader { return strings.NewReader(s) }

func newEngine(t *testing.T, now time.Time) (*Engine, *store.DB) {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Engine{DB: db, Now: func() time.Time { return now }}, db
}

// matureReporter ensures a reporter row exists whose created_at pre-dates the
// maturation delay, so it counts toward promotion distinctness. Consensus gates
// immature reporter_ids out of the promotion thresholds (Sybil defense); the
// test fixtures model established reporters.
func matureReporter(t *testing.T, db *store.DB, id string) {
	t.Helper()
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if _, err := db.Exec(`INSERT OR IGNORE INTO reporters
        (reporter_id, secret_hash, capabilities, vedetta_version, created_at, status)
        VALUES (?, 'hash', '[]', '0.1.0', ?, 'active')`, id, old); err != nil {
		t.Fatal(err)
	}
}

// addSignal inserts a deduped signal for a reporter within the window.
func addSignal(t *testing.T, db *store.DB, reporter, kind, indicator string, conf float64, reasons string, bucket time.Time) {
	t.Helper()
	matureReporter(t, db, reporter)
	row := store.SignalRow{
		ReporterID: reporter, Kind: kind, IndicatorKey: indicator,
		TimeBucket: bucket.UTC().Format(time.RFC3339), LocalConfidence: conf,
		LocalReasons: reasons, ObservationCount: 1, DistinctAssetCount: 1,
	}
	switch kind {
	case ingest.KindKnownBad:
		row.Domain = indicator
		row.EtldPlusOne = etldOf(indicator)
	case ingest.KindCandidate:
		row.EtldPlusOne = indicator
	case ingest.KindBehavior:
		row.Behavior = indicator
	}
	if _, err := db.UpsertSignal(row); err != nil {
		t.Fatal(err)
	}
}

func etldOf(domain string) string {
	// crude: last two labels; fixtures use two-label eTLD+1 under .example
	return domain
}

func liveFeed(t *testing.T, db *store.DB, now time.Time) []store.FeedItem {
	t.Helper()
	items, _, err := db.LiveFeedItems(store.FeedQuery{Now: now, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// addSignalImmature inserts a signal for a reporter registered "just now" (after
// the maturation cutoff), i.e. a Sybil-freshly-minted reporter_id.
func addSignalImmature(t *testing.T, db *store.DB, now time.Time, reporter, kind, indicator string, conf float64, reasons string, bucket time.Time) {
	t.Helper()
	if _, err := db.Exec(`INSERT OR IGNORE INTO reporters
        (reporter_id, secret_hash, capabilities, vedetta_version, created_at, status)
        VALUES (?, 'hash', '[]', '0.1.0', ?, 'active')`, reporter, now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	row := store.SignalRow{
		ReporterID: reporter, Kind: kind, IndicatorKey: indicator,
		TimeBucket: bucket.UTC().Format(time.RFC3339), LocalConfidence: conf,
		LocalReasons: reasons, ObservationCount: 1, DistinctAssetCount: 1,
	}
	switch kind {
	case ingest.KindKnownBad:
		row.Domain = indicator
		row.EtldPlusOne = etldOf(indicator)
	case ingest.KindCandidate:
		row.EtldPlusOne = indicator
	case ingest.KindBehavior:
		row.Behavior = indicator
	}
	if _, err := db.UpsertSignal(row); err != nil {
		t.Fatal(err)
	}
}

// TestSybilFreshReportersDoNotPromote is the finding #1 regression: a single
// actor registering several fresh reporter_ids and sending the identical signal
// from each must NOT be able to promote an indicator. Immature reporter_ids are
// excluded from the promotion distinctness thresholds, so N brand-new ids count
// as zero mature sources. Once the ids age past the maturation delay, the same
// signals promote — proving the gate is a maturation delay, not a permanent ban.
func TestSybilFreshReportersDoNotPromote(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	e, db := newEngine(t, now)

	// Four freshly-minted reporter_ids all send the same known_bad domain — enough
	// distinct ids to satisfy every rule's count, but all immature.
	for _, r := range []string{"sybil1", "sybil2", "sybil3", "sybil4"} {
		addSignalImmature(t, db, now, r, ingest.KindKnownBad, "kb.badzone.example", 0.99, `["known_bad"]`, bucket)
	}
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if got := len(liveFeed(t, db, now)); got != 0 {
		t.Fatalf("fresh Sybil reporters must NOT promote; got %d feed items", got)
	}

	// Age all four past the maturation delay → now the same signals promote.
	if _, err := db.Exec(`UPDATE reporters SET created_at = ?`,
		now.Add(-2*ReporterMaturationDelay).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if got := len(liveFeed(t, db, now)); got != 1 {
		t.Fatalf("matured reporters must promote; got %d feed items", got)
	}
}

func TestKnownBadNeedsTwoReporters(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)

	// One reporter → NOT promoted.
	e, db := newEngine(t, now)
	addSignal(t, db, "r1", ingest.KindKnownBad, "kb.badzone.example", 0.99, `["known_bad"]`, bucket)
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db, now)) != 0 {
		t.Fatal("single reporter must NOT promote a known_bad indicator")
	}

	// Second independent reporter → promoted (rule 1).
	addSignal(t, db, "r2", ingest.KindKnownBad, "kb.badzone.example", 0.99, `["known_bad"]`, bucket)
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	feed := liveFeed(t, db, now)
	if len(feed) != 1 {
		t.Fatalf("two reporters must promote, got %d items", len(feed))
	}
	if feed[0].Severity != "high" || feed[0].SourcesRequired != 2 {
		t.Fatalf("unexpected feed item: %+v", feed[0])
	}
}

func TestExactDomainRuleTwoBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)

	// Rule 2: exact domain (no known_bad), needs >=3 reporters AND avg>=0.90.
	// 2 reporters at 0.95 → below distinct threshold, not promoted.
	e, db := newEngine(t, now)
	addSignal(t, db, "r1", ingest.KindKnownBad, "rule2.badzone.example", 0.95, `["c2_candidate"]`, bucket)
	addSignal(t, db, "r2", ingest.KindKnownBad, "rule2.badzone.example", 0.95, `["c2_candidate"]`, bucket)
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db, now)) != 0 {
		t.Fatal("2 reporters without known_bad must not promote under rule 2")
	}

	// 3 reporters but avg 0.89 → still not promoted.
	e2, db2 := newEngine(t, now)
	addSignal(t, db2, "r1", ingest.KindKnownBad, "d.badzone.example", 0.89, `["c2_candidate"]`, bucket)
	addSignal(t, db2, "r2", ingest.KindKnownBad, "d.badzone.example", 0.89, `["c2_candidate"]`, bucket)
	addSignal(t, db2, "r3", ingest.KindKnownBad, "d.badzone.example", 0.89, `["c2_candidate"]`, bucket)
	if err := e2.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db2, now)) != 0 {
		t.Fatal("avg 0.89 must not promote under rule 2 (needs 0.90)")
	}

	// 3 reporters at 0.90 → promoted (medium).
	e3, db3 := newEngine(t, now)
	addSignal(t, db3, "r1", ingest.KindKnownBad, "e.badzone.example", 0.90, `["c2_candidate"]`, bucket)
	addSignal(t, db3, "r2", ingest.KindKnownBad, "e.badzone.example", 0.90, `["c2_candidate"]`, bucket)
	addSignal(t, db3, "r3", ingest.KindKnownBad, "e.badzone.example", 0.90, `["c2_candidate"]`, bucket)
	if err := e3.Run(); err != nil {
		t.Fatal(err)
	}
	feed := liveFeed(t, db3, now)
	if len(feed) != 1 || feed[0].Severity != "medium" {
		t.Fatalf("3 reporters at 0.90 must promote medium, got %+v", feed)
	}
}

func TestClusterRuleThreeBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)

	// 3 reporters at 0.85 → below distinct threshold (needs 4).
	e, db := newEngine(t, now)
	for _, r := range []string{"r1", "r2", "r3"} {
		addSignal(t, db, r, ingest.KindCandidate, "cluster.example", 0.85, `["dga_candidate"]`, bucket)
	}
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db, now)) != 0 {
		t.Fatal("3 reporters must not promote a cluster (needs 4)")
	}

	// 4 reporters at 0.79 → below confidence threshold.
	e2, db2 := newEngine(t, now)
	for _, r := range []string{"r1", "r2", "r3", "r4"} {
		addSignal(t, db2, r, ingest.KindCandidate, "c79.example", 0.79, `["dga_candidate"]`, bucket)
	}
	if err := e2.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db2, now)) != 0 {
		t.Fatal("avg 0.79 must not promote cluster (needs 0.80)")
	}

	// 4 reporters at 0.80 → promoted (low).
	e3, db3 := newEngine(t, now)
	for _, r := range []string{"r1", "r2", "r3", "r4"} {
		addSignal(t, db3, r, ingest.KindCandidate, "c80.example", 0.80, `["dga_candidate"]`, bucket)
	}
	if err := e3.Run(); err != nil {
		t.Fatal(err)
	}
	feed := liveFeed(t, db3, now)
	if len(feed) != 1 || feed[0].Severity != "low" || feed[0].Kind != "etld1_indicator" {
		t.Fatalf("4 reporters at 0.80 must promote low etld1, got %+v", feed)
	}
}

func TestPerReporterInfluenceCap(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	e, db := newEngine(t, now)

	// 100 signals from ONE reporter across distinct buckets → counts once.
	base := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		addSignal(t, db, "r1", ingest.KindKnownBad, "flood.badzone.example", 0.99,
			`["known_bad"]`, base.Add(time.Duration(i)*time.Hour))
	}
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	// Never promoted (distinct_reporters == 1).
	if len(liveFeed(t, db, now)) != 0 {
		t.Fatal("100 signals from one reporter must not promote (distinct=1)")
	}
	var distinct int
	db.QueryRow(`SELECT distinct_reporters FROM signal_aggregates WHERE indicator_key='flood.badzone.example'`).Scan(&distinct)
	if distinct != 1 {
		t.Fatalf("expected distinct_reporters=1, got %d", distinct)
	}
}

func TestConfidenceRisesWithReporters(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)

	confFor := func(nReporters int) float64 {
		e, db := newEngine(t, now)
		for i := 0; i < nReporters; i++ {
			addSignal(t, db, rid(i), ingest.KindKnownBad, "rise.badzone.example", 0.99,
				`["known_bad"]`, bucket)
		}
		if err := e.Run(); err != nil {
			t.Fatal(err)
		}
		feed := liveFeed(t, db, now)
		if len(feed) != 1 {
			t.Fatalf("expected promotion at %d reporters", nReporters)
		}
		return feed[0].Confidence
	}

	c2 := confFor(2)
	c5 := confFor(5)
	if !(c5 > c2) {
		t.Fatalf("confidence must rise with independent reporters: c2=%v c5=%v", c2, c5)
	}
}

func rid(i int) string {
	return "r" + string(rune('A'+i))
}

func TestAllowlistGuardBlocksPromotion(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	e, db := newEngine(t, now)

	// Allowlist the eTLD+1 the known_bad indicator reduces to.
	if _, err := db.LoadAllowlist(readerString("popular.example")); err != nil {
		t.Fatal(err)
	}
	// Two reporters would normally promote (rule 1), but the eTLD+1 is allowlisted.
	addSignalWithEtld(t, db, "r1", "kb.popular.example", "popular.example", bucket)
	addSignalWithEtld(t, db, "r2", "kb.popular.example", "popular.example", bucket)
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db, now)) != 0 {
		t.Fatal("allowlisted eTLD+1 must never promote")
	}
	// Reporters flagged for allowlist poisoning.
	day := now.UTC().Format("2006-01-02")
	c, _ := db.GetCounters("r1", day)
	if c.AllowlistFlags == 0 {
		t.Fatal("expected allowlist_flags incremented on r1")
	}
}

func addSignalWithEtld(t *testing.T, db *store.DB, reporter, domain, etld string, bucket time.Time) {
	t.Helper()
	if _, err := db.UpsertSignal(store.SignalRow{
		ReporterID: reporter, Kind: ingest.KindKnownBad, IndicatorKey: domain,
		Domain: domain, EtldPlusOne: etld, TimeBucket: bucket.UTC().Format(time.RFC3339),
		LocalConfidence: 0.99, LocalReasons: `["known_bad"]`, ObservationCount: 1, DistinctAssetCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDecayRevokesStaleItems(t *testing.T) {
	promoteAt := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)

	// Promote a cluster (rule 3 → 7-day TTL from last_seen 14:00 → expires 07-10 14:00).
	e, db := newEngine(t, promoteAt)
	for _, r := range []string{"r1", "r2", "r3", "r4"} {
		addSignal(t, db, r, ingest.KindCandidate, "decayme.example", 0.85, `["dga_candidate"]`, bucket)
	}
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db, promoteAt)) != 1 {
		t.Fatal("expected 1 promoted item")
	}

	// Advance past expiry with no fresh signals in-window. Purge old signals so
	// the aggregate no longer refreshes last_seen.
	future := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	db.PurgeSignals(future.Add(-Window))
	e.Now = func() time.Time { return future }
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	if len(liveFeed(t, db, future)) != 0 {
		t.Fatal("stale item must decay out of the live feed")
	}
}

func TestConsensusIdempotent(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	bucket := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	e, db := newEngine(t, now)
	addSignal(t, db, "r1", ingest.KindKnownBad, "idem.badzone.example", 0.99, `["known_bad"]`, bucket)
	addSignal(t, db, "r2", ingest.KindKnownBad, "idem.badzone.example", 0.99, `["known_bad"]`, bucket)
	if err := e.Run(); err != nil {
		t.Fatal(err)
	}
	first := liveFeed(t, db, now)
	if err := e.Run(); err != nil { // re-run converges to identical state
		t.Fatal(err)
	}
	second := liveFeed(t, db, now)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected 1 item each run, got %d then %d", len(first), len(second))
	}
	if first[0].FeedID != second[0].FeedID || first[0].Confidence != second[0].Confidence {
		t.Fatal("consensus re-run must be idempotent (stable feed_id + confidence)")
	}
}
