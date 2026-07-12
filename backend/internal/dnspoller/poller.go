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

// Poller periodically fetches DNS queries from a Pi-hole instance and ingests them.
type Poller struct {
	client       *PiHoleClient
	db           *store.DB
	processor    *processing.Processor
	activityLog  *api.ActivityLog
	interval     time.Duration
	lastPollTime time.Time
	mu           sync.Mutex
	stopCh       chan struct{}
	doneCh       chan struct{}
}

const piHoleReplayOverlap = 2 * time.Minute

// NewPoller creates a new DNS poller for Pi-hole.
func NewPoller(
	pihole *PiHoleClient,
	db *store.DB,
	processor *processing.Processor,
	activityLog *api.ActivityLog,
	interval time.Duration,
) *Poller {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &Poller{
		client:      pihole,
		db:          db,
		processor:   processor,
		activityLog: activityLog,
		interval:    interval,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

// Start begins the polling loop in a background goroutine.
func (p *Poller) Start() {
	go p.run()
}

// Stop gracefully stops the poller.
func (p *Poller) Stop() {
	close(p.stopCh)
	<-p.doneCh
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.client.Close(ctx); err != nil {
		log.Printf("dnspoller: Pi-hole session logout failed: %v", err)
	}
}

// SetInterval updates the polling interval (thread-safe).
func (p *Poller) SetInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	p.mu.Lock()
	p.interval = interval
	p.mu.Unlock()
}

// run is the main polling loop.
func (p *Poller) run() {
	defer close(p.doneCh)

	p.activityLog.Info("ingest", fmt.Sprintf("Pi-hole poller started — polling every %s", p.interval))

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
			p.activityLog.Info("ingest", "Pi-hole poller stopped")
			return
		}
	}
}

// poll fetches new queries and ingests them.
func (p *Poller) poll() {
	now := time.Now().UTC()
	_ = p.db.MarkCollectionAttempt(context.Background(), "pihole", "dns_poller", "Pi-hole", now)
	p.mu.Lock()
	lastTime := p.lastPollTime
	p.mu.Unlock()

	// Replay a bounded window on every successful poll. Deterministic upstream
	// query IDs make duplicates harmless, and the overlap closes snapshot races.
	from := lastTime
	if from.IsZero() {
		from = now.Add(-piHoleReplayOverlap)
	}
	to := now

	// Fetch queries from Pi-hole
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	queries, err := p.client.FetchQueries(ctx, from, to)
	cancel()

	if err != nil {
		_ = p.db.MarkCollectionError(context.Background(), "pihole", "dns_poller", "Pi-hole", "query fetch failed", time.Now().UTC())
		p.activityLog.Warn("ingest", fmt.Sprintf("Pi-hole unreachable: %v", err))
		log.Printf("dnspoller: fetch error: %v", err)
		return
	}
	nextPollTime := piHoleReplayWatermark(to, queries)

	if len(queries) == 0 {
		// No new queries
		p.mu.Lock()
		p.lastPollTime = nextPollTime
		p.mu.Unlock()
		_ = p.db.MarkCollectionSuccess(context.Background(), "pihole", "dns_poller", "Pi-hole", 0, time.Now().UTC())
		return
	}

	// Convert Pi-hole queries to Vedetta events
	events := make([]models.Event, 0, len(queries))
	for _, q := range queries {
		event := p.piHoleQueryToEvent(q)
		if event != nil {
			events = append(events, *event)
		}
	}

	if len(events) == 0 {
		p.mu.Lock()
		p.lastPollTime = nextPollTime
		p.mu.Unlock()
		_ = p.db.MarkCollectionSuccess(context.Background(), "pihole", "dns_poller", "Pi-hole", 0, time.Now().UTC())
		return
	}

	inserted, duplicates, findingEvents, err := processPollerEvents(context.Background(), p.processor, events, "pihole")
	if err != nil {
		_ = p.db.MarkCollectionError(context.Background(), "pihole", "dns_poller", "Pi-hole", "event processing failed", time.Now().UTC())
		p.activityLog.Error("ingest", fmt.Sprintf("Failed to insert DNS queries: %v", err))
		log.Printf("dnspoller: insert error: %v", err)
		return
	}

	// Update last poll time
	p.mu.Lock()
	p.lastPollTime = nextPollTime
	p.mu.Unlock()
	accepted := inserted + duplicates
	_ = p.db.MarkCollectionSuccess(context.Background(), "pihole", "dns_poller", "Pi-hole", int64(accepted), time.Now().UTC())

	// Log success
	msg := fmt.Sprintf("Ingested %d DNS queries (%d duplicates, %d produced findings)", accepted, duplicates, findingEvents)
	p.activityLog.Info("ingest", msg)
	log.Printf("dnspoller: %s", msg)
}

func piHoleReplayWatermark(to time.Time, queries []PiHoleQuery) time.Time {
	next := to.UTC().Add(-piHoleReplayOverlap)
	for _, query := range queries {
		if !piHoleQueryPending(query) {
			continue
		}
		queryTime := piHoleQueryTime(query)
		if !queryTime.After(next) {
			// Keep the boundary strictly before the mutable row. This remains held
			// across polls until Pi-hole finalizes or removes that query.
			next = queryTime.Add(-time.Nanosecond)
		}
	}
	return next
}

func piHoleQueryPending(query PiHoleQuery) bool {
	return query.Status == 0 || query.Status == 14
}

// piHoleQueryToEvent converts a Pi-hole query to a Vedetta Event.
// Returns nil if the query is invalid or should be skipped.
func (p *Poller) piHoleQueryToEvent(q PiHoleQuery) *models.Event {
	if piHoleQueryPending(q) {
		return nil
	}
	// Validate required fields
	if q.Domain == "" || q.ClientIP == "" {
		return nil
	}

	// Normalize query_type
	queryType := normalizeQueryType(q.QueryType)

	// Map Pi-hole status to blocked boolean
	blocked := q.IsBlocked()

	event := &models.Event{
		EventID:        piHoleEventID(q),
		Timestamp:      piHoleQueryTime(q),
		EventType:      "dns_query",
		SourceHash:     "", // Core processor derives the per-install HMAC.
		SourceIP:       q.ClientIP,
		Domain:         q.Domain,
		QueryType:      queryType,
		ResolvedIP:     q.CNAMETarget, // Use CNAME target if available, else empty
		Blocked:        blocked,
		AnomalyScore:   0.0, // Will be set by enricher
		Tags:           []string{},
		Geo:            "",
		DeviceVendor:   "",
		NetworkSegment: "default",
		DNSSource:      "pihole",
	}

	// Preserve the source response as evidence for the unified processor. Pi-hole
	// exposes a CNAME target rather than a complete answer set on this API; keeping
	// it in dns_answers lets observable extraction classify it as a CNAME while the
	// legacy ResolvedIP projection remains backward compatible.
	metadata := map[string]any{
		"pihole_status":     q.Status,
		"pihole_reply_type": q.ReplyType,
		"dnssec_status":     q.DNSSEC,
		"reply_time_ms":     q.ReplyTime,
	}
	if q.QueryID != 0 {
		metadata["pihole_query_id"] = q.QueryID
	}
	if q.StatusName != "" {
		metadata["pihole_status_name"] = q.StatusName
	}
	if q.DNSSECName != "" {
		metadata["pihole_dnssec_name"] = q.DNSSECName
	}
	if q.ReplyName != "" {
		metadata["pihole_reply_name"] = q.ReplyName
	}
	if q.CNAMETarget != "" {
		metadata["dns_answers"] = []string{q.CNAMETarget}
	}
	if q.RegexID != "" {
		metadata["pihole_regex_id"] = q.RegexID
	}
	if raw, err := json.Marshal(metadata); err == nil {
		event.Metadata = string(raw)
	}

	return event
}

// normalizeQueryType maps Pi-hole query type strings to standard DNS types.
func normalizeQueryType(qtype string) string {
	switch qtype {
	case "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "SOA", "NS", "PTR", "SPF":
		return qtype
	case "UNKNOWN":
		return ""
	default:
		// Keep as-is if it's already a standard type
		if qtype != "" {
			return qtype
		}
		return ""
	}
}
