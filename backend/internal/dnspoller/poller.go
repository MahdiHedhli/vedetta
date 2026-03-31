package dnspoller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/api"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// Poller periodically fetches DNS queries from a Pi-hole instance and ingests them.
type Poller struct {
	client       *PiHoleClient
	db           *store.DB
	enricher     *dnsintel.Enricher
	activityLog  *api.ActivityLog
	installSalt  string
	interval     time.Duration
	lastPollTime time.Time
	mu           sync.Mutex
	stopCh       chan struct{}
	doneCh       chan struct{}
}

// NewPoller creates a new DNS poller for Pi-hole.
func NewPoller(
	pihole *PiHoleClient,
	db *store.DB,
	enricher *dnsintel.Enricher,
	activityLog *api.ActivityLog,
	installSalt string,
	interval time.Duration,
) *Poller {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &Poller{
		client:      pihole,
		db:          db,
		enricher:    enricher,
		activityLog: activityLog,
		installSalt: installSalt,
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
	p.mu.Lock()
	lastTime := p.lastPollTime
	p.mu.Unlock()

	// If this is the first poll, fetch from 1 minute ago
	from := lastTime
	if from.IsZero() {
		from = time.Now().Add(-1 * time.Minute)
	}
	to := time.Now()

	// Fetch queries from Pi-hole
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	queries, err := p.client.FetchQueries(ctx, from, to)
	cancel()

	if err != nil {
		p.activityLog.Warn("ingest", fmt.Sprintf("Pi-hole unreachable: %v", err))
		log.Printf("dnspoller: fetch error: %v", err)
		return
	}

	if len(queries) == 0 {
		// No new queries
		p.mu.Lock()
		p.lastPollTime = to
		p.mu.Unlock()
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
		p.lastPollTime = to
		p.mu.Unlock()
		return
	}

	// Enrich events through the threat detection pipeline
	enrichedCount := 0
	for i := range events {
		p.enricher.Enrich(&events[i])
		if len(events[i].Tags) > 0 || events[i].AnomalyScore > 0 {
			enrichedCount++
		}
	}

	// Insert into database
	inserted, err := p.db.InsertEvents(events)
	if err != nil {
		p.activityLog.Error("ingest", fmt.Sprintf("Failed to insert DNS queries: %v", err))
		log.Printf("dnspoller: insert error: %v", err)
		return
	}

	// Update last poll time
	p.mu.Lock()
	p.lastPollTime = to
	p.mu.Unlock()

	// Log success
	msg := fmt.Sprintf("Ingested %d DNS queries (%d with threat signals)", inserted, enrichedCount)
	p.activityLog.Info("ingest", msg)
	log.Printf("dnspoller: %s", msg)
}

// piHoleQueryToEvent converts a Pi-hole query to a Vedetta Event.
// Returns nil if the query is invalid or should be skipped.
func (p *Poller) piHoleQueryToEvent(q PiHoleQuery) *models.Event {
	// Validate required fields
	if q.Domain == "" || q.ClientIP == "" {
		return nil
	}

	// Generate event ID
	eventID := uuid.New().String()

	// Compute source_hash as HMAC-SHA256(clientIP, installSalt)
	h := hmac.New(sha256.New, []byte(p.installSalt))
	h.Write([]byte(q.ClientIP))
	sourceHash := hex.EncodeToString(h.Sum(nil))

	// Normalize query_type
	queryType := normalizeQueryType(q.QueryType)

	// Map Pi-hole status to blocked boolean
	blocked := q.IsBlocked()

	event := &models.Event{
		EventID:       eventID,
		Timestamp:     time.Unix(q.Timestamp, 0).UTC(),
		EventType:     "dns_query",
		SourceHash:    sourceHash,
		Domain:        q.Domain,
		QueryType:     queryType,
		ResolvedIP:    q.CNAMETarget, // Use CNAME target if available, else empty
		Blocked:       blocked,
		AnomalyScore:  0.0, // Will be set by enricher
		Tags:          []string{},
		Geo:           "",
		DeviceVendor:  "",
		NetworkSegment: "default",
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
