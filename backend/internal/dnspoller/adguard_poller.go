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

// AdGuardPoller periodically fetches DNS queries from an AdGuard Home instance
// and ingests them as Vedetta events.
type AdGuardPoller struct {
	client       *AdGuardHTTPClient
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

// NewAdGuardPoller creates a new DNS poller for AdGuard Home.
func NewAdGuardPoller(
	client *AdGuardHTTPClient,
	db *store.DB,
	enricher *dnsintel.Enricher,
	activityLog *api.ActivityLog,
	installSalt string,
	interval time.Duration,
) *AdGuardPoller {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &AdGuardPoller{
		client:      client,
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	queries, err := p.client.FetchQueries(ctx, 100)
	cancel()

	if err != nil {
		p.activityLog.Warn("ingest", fmt.Sprintf("AdGuard unreachable: %v", err))
		log.Printf("dnspoller/adguard: fetch error: %v", err)
		return
	}

	if len(queries) == 0 {
		// No new queries
		p.mu.Lock()
		p.lastPollTime = time.Now()
		p.mu.Unlock()
		return
	}

	// Filter to only new queries (those after lastPollTime)
	p.mu.Lock()
	lastTime := p.lastPollTime
	p.mu.Unlock()

	var newQueries []AdGuardQuery
	var maxTime time.Time

	for _, q := range queries {
		if q.Time.After(lastTime) {
			newQueries = append(newQueries, q)
			if q.Time.After(maxTime) {
				maxTime = q.Time
			}
		}
	}

	if len(newQueries) == 0 {
		// No new queries since last poll
		p.mu.Lock()
		p.lastPollTime = time.Now()
		p.mu.Unlock()
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
		p.mu.Lock()
		p.lastPollTime = time.Now()
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
		log.Printf("dnspoller/adguard: insert error: %v", err)
		return
	}

	// Update last poll time
	p.mu.Lock()
	p.lastPollTime = maxTime
	p.mu.Unlock()

	// Log success
	msg := fmt.Sprintf("Ingested %d DNS queries from AdGuard (%d with threat signals)", inserted, enrichedCount)
	p.activityLog.Info("ingest", msg)
	log.Printf("dnspoller/adguard: %s", msg)
}

// adguardQueryToEvent converts an AdGuard query to a Vedetta Event.
// Returns nil if the query is invalid or should be skipped.
func (p *AdGuardPoller) adguardQueryToEvent(q AdGuardQuery) *models.Event {
	// Validate required fields
	if q.Question.Name == "" || q.Client == "" {
		return nil
	}

	// Generate event ID
	eventID := uuid.New().String()

	// Compute source_hash as HMAC-SHA256(clientIP, installSalt)
	h := hmac.New(sha256.New, []byte(p.installSalt))
	h.Write([]byte(q.Client))
	sourceHash := hex.EncodeToString(h.Sum(nil))

	// Normalize query type
	queryType := normalizeQueryType(q.Question.Type)

	// Map AdGuard status to blocked boolean
	blocked := q.IsBlocked()

	// Extract resolved IP from answer if available
	var resolvedIP string
	if len(q.Answer) > 0 && q.Answer[0].Value != "" {
		resolvedIP = q.Answer[0].Value
	}

	event := &models.Event{
		EventID:        eventID,
		Timestamp:      q.Time.UTC(),
		EventType:      "dns_query",
		SourceHash:     sourceHash,
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

	return event
}
