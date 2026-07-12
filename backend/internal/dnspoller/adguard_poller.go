package dnspoller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/api"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/processing"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// AdGuardPoller periodically fetches DNS queries from an AdGuard Home instance
// and ingests them as Vedetta events.
type AdGuardPoller struct {
	client       *AdGuardHTTPClient
	db           *store.DB
	processor    *processing.Processor
	activityLog  *api.ActivityLog
	interval     time.Duration
	lastPollTime time.Time
	// A burst larger than one bounded fetch is drained oldest-ward over later
	// polls. The committed timestamp does not move until the continuation reaches
	// the prior watermark, so no unseen middle of the burst can be skipped.
	backfillCursor  string
	backfillMaxTime time.Time
	mu              sync.Mutex
	stopCh          chan struct{}
	doneCh          chan struct{}
}

const adGuardWatermarkFutureSkew = time.Hour

// NewAdGuardPoller creates a new DNS poller for AdGuard Home.
func NewAdGuardPoller(
	client *AdGuardHTTPClient,
	db *store.DB,
	processor *processing.Processor,
	activityLog *api.ActivityLog,
	interval time.Duration,
) *AdGuardPoller {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &AdGuardPoller{
		client:      client,
		db:          db,
		processor:   processor,
		activityLog: activityLog,
		interval:    interval,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

// Start begins the polling loop in a background goroutine.
func (p *AdGuardPoller) Start() {
	go p.run()
}

// Stop gracefully stops the poller.
func (p *AdGuardPoller) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// SetInterval updates the polling interval (thread-safe).
func (p *AdGuardPoller) SetInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	p.mu.Lock()
	p.interval = interval
	p.mu.Unlock()
}

// run is the main polling loop.
func (p *AdGuardPoller) run() {
	defer close(p.doneCh)

	p.activityLog.Info("ingest", fmt.Sprintf("AdGuard poller started — polling every %s", p.interval))

	// Initial poll immediately
	p.poll()

	// Then poll on interval
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.poll()
		case <-p.stopCh:
			p.activityLog.Info("ingest", "AdGuard poller stopped")
			return
		}
	}
}

// poll fetches new queries and ingests them.
func (p *AdGuardPoller) poll() {
	// AdGuard doesn't support time-range filtering in the same way as Pi-hole,
	// so we fetch the most recent queries and track them by timestamp
	// to avoid re-processing.

	_ = p.db.MarkCollectionAttempt(context.Background(), "adguard", "dns_poller", "AdGuard Home", time.Now().UTC())
	p.mu.Lock()
	lastTime := p.lastPollTime
	startCursor := p.backfillCursor
	cycleMaxTime := p.backfillMaxTime
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	batch, err := p.client.fetchQueryBatch(ctx, adGuardMaxQueries, startCursor)
	cancel()

	if err != nil {
		_ = p.db.MarkCollectionError(context.Background(), "adguard", "dns_poller", "AdGuard Home", "query fetch failed", time.Now().UTC())
		p.activityLog.Warn("ingest", fmt.Sprintf("AdGuard unreachable: %v", err))
		log.Printf("dnspoller/adguard: fetch error: %v", err)
		return
	}
	queries := batch.Queries

	if len(queries) == 0 {
		// An empty continuation completes the bounded traversal. Never advance a
		// new/idle poll to Core's wall clock: the watermark stays in AdGuard's clock
		// domain so clock skew cannot make a later real record look old.
		if startCursor != "" && batch.Complete {
			p.commitAdGuardBatch(true, cycleMaxTime, "")
		}
		_ = p.db.MarkCollectionSuccess(context.Background(), "adguard", "dns_poller", "AdGuard Home", 0, time.Now().UTC())
		return
	}

	newQueries, maxTime := adGuardQueriesSince(queries, lastTime, time.Now().UTC().Add(adGuardWatermarkFutureSkew))
	if maxTime.After(cycleMaxTime) {
		cycleMaxTime = maxTime
	}
	// A fresh install bootstraps from the bounded newest prefix: historical query
	// retention must not delay current detection for dozens of poll intervals.
	// Once a watermark exists, a burst is drained until traversal reaches that
	// timestamp (or the retained log ends), so post-bootstrap events are not lost.
	completeCycle := lastTime.IsZero() || batch.Complete || adGuardBatchReachesWatermark(queries, lastTime)

	if len(newQueries) == 0 {
		p.commitAdGuardBatch(completeCycle, cycleMaxTime, batch.NextCursor)
		_ = p.db.MarkCollectionSuccess(context.Background(), "adguard", "dns_poller", "AdGuard Home", 0, time.Now().UTC())
		return
	}

	// Convert AdGuard queries to Vedetta events
	events := make([]models.Event, 0, len(newQueries))
	for _, q := range newQueries {
		event := p.adguardQueryToEvent(q)
		if event != nil {
			events = append(events, *event)
		}
	}

	if len(events) == 0 {
		// Do not acknowledge a timestamp whose records were all invalid. A fixed
		// adapter or corrected upstream record must still be eligible next poll;
		// likewise, do not advance a backfill cursor past invalid evidence.
		_ = p.db.MarkCollectionSuccess(context.Background(), "adguard", "dns_poller", "AdGuard Home", 0, time.Now().UTC())
		return
	}

	inserted, duplicates, findingEvents, err := processPollerEvents(context.Background(), p.processor, events, "adguard")
	if err != nil {
		_ = p.db.MarkCollectionError(context.Background(), "adguard", "dns_poller", "AdGuard Home", "event processing failed", time.Now().UTC())
		p.activityLog.Error("ingest", fmt.Sprintf("Failed to insert DNS queries: %v", err))
		log.Printf("dnspoller/adguard: insert error: %v", err)
		return
	}

	p.commitAdGuardBatch(completeCycle, cycleMaxTime, batch.NextCursor)
	accepted := inserted + duplicates
	_ = p.db.MarkCollectionSuccess(context.Background(), "adguard", "dns_poller", "AdGuard Home", int64(accepted), time.Now().UTC())

	// Log success
	msg := fmt.Sprintf("Ingested %d DNS queries from AdGuard (%d duplicates, %d produced findings)", accepted, duplicates, findingEvents)
	if !completeCycle {
		msg += " — bounded backlog will continue next poll"
	}
	p.activityLog.Info("ingest", msg)
	log.Printf("dnspoller/adguard: %s", msg)
}

func (p *AdGuardPoller) commitAdGuardBatch(complete bool, cycleMax time.Time, nextCursor string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if complete {
		p.lastPollTime = cycleMax
		p.backfillCursor = ""
		p.backfillMaxTime = time.Time{}
		return
	}
	p.backfillCursor = nextCursor
	p.backfillMaxTime = cycleMax
}

func adGuardBatchReachesWatermark(queries []AdGuardQuery, watermark time.Time) bool {
	if watermark.IsZero() {
		return true
	}
	for _, query := range queries {
		if !query.Time.After(watermark) {
			return true
		}
	}
	return false
}

// adGuardQueriesSince retains a one-timestamp overlap. AdGuard does not expose
// a durable cursor, and several records can share the same timestamp. The
// deterministic event IDs make replaying that boundary safe while preventing a
// same-timestamp record first visible on a later snapshot from being skipped.
// The returned watermark is derived only from upstream timestamps.
func adGuardQueriesSince(queries []AdGuardQuery, watermark, latestAdvance time.Time) ([]AdGuardQuery, time.Time) {
	selected := make([]AdGuardQuery, 0, len(queries))
	maxTime := watermark
	for _, query := range queries {
		if !watermark.IsZero() && query.Time.Before(watermark) {
			continue
		}
		selected = append(selected, query)
		// Process a future-skewed record (the unified processor clamps its event
		// time), but never let it poison the poll cursor and strand normal traffic.
		if query.Time.After(maxTime) && (latestAdvance.IsZero() || !query.Time.After(latestAdvance)) {
			maxTime = query.Time
		}
	}
	return selected, maxTime
}

// adguardQueryToEvent converts an AdGuard query to a Vedetta Event.
// Returns nil if the query is invalid or should be skipped.
func (p *AdGuardPoller) adguardQueryToEvent(q AdGuardQuery) *models.Event {
	// Validate required fields
	if q.Question.Name == "" || q.Client == "" {
		return nil
	}

	// Normalize query type
	queryType := normalizeQueryType(q.Question.Type)

	// Map AdGuard status to blocked boolean
	blocked := q.IsBlocked()

	// Keep the first answer in the legacy projection and preserve every answer
	// for typed IOC evaluation. A response can contain a CNAME followed by one or
	// more addresses; checking only Answer[0] misses destination-IP intelligence.
	var resolvedIP string
	answers := make([]string, 0, len(q.Answer))
	for _, answer := range q.Answer {
		if answer.Value == "" {
			continue
		}
		answers = append(answers, answer.Value)
		if resolvedIP == "" {
			resolvedIP = answer.Value
		}
	}
	originalAnswers := make([]string, 0, len(q.OriginalAnswer))
	for _, answer := range q.OriginalAnswer {
		if answer.Value != "" {
			originalAnswers = append(originalAnswers, answer.Value)
		}
	}

	event := &models.Event{
		EventID:        adGuardEventID(q),
		Timestamp:      q.Time.UTC(),
		EventType:      "dns_query",
		SourceHash:     "", // Core processor derives the per-install HMAC.
		SourceIP:       q.Client,
		Domain:         q.Question.Name,
		QueryType:      queryType,
		ResolvedIP:     resolvedIP,
		Blocked:        blocked,
		AnomalyScore:   0.0, // Will be set by enricher
		Tags:           []string{},
		Geo:            "",
		DeviceVendor:   "",
		NetworkSegment: "default",
		DNSSource:      "adguard",
	}

	metadata := map[string]any{
		"adguard_reason": q.Reason,
		"elapsed_ms":     q.ElapsedMs,
	}
	if len(answers) > 0 {
		metadata["dns_answers"] = answers
	}
	if len(originalAnswers) > 0 {
		metadata["dns_original_answers"] = originalAnswers
	}
	if q.Upstream != "" {
		metadata["upstream"] = q.Upstream
	}
	if len(q.Rules) > 0 {
		metadata["adguard_rules"] = q.Rules
	}
	if q.Rule != "" {
		metadata["adguard_rule"] = q.Rule
	}
	if q.FilterID != 0 {
		metadata["adguard_filter_id"] = q.FilterID
	}
	if q.ClientInfo.Name != "" {
		metadata["client_name"] = q.ClientInfo.Name
	}
	if raw, err := json.Marshal(metadata); err == nil {
		event.Metadata = string(raw)
	}

	return event
}
