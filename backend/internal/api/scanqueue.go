package api

import (
	"sync"
	"time"
)

// ScanRequest represents a queued scan from the UI or sensor work dispatcher.
type ScanRequest struct {
	CIDR      string    `json:"cidr"`
	Segment   string    `json:"segment"`
	ScanPorts bool      `json:"scan_ports"`
	RequestedAt time.Time `json:"requested_at"`
}

// ScanQueue manages pending scan requests with thread-safe operations.
type ScanQueue struct {
	mu       sync.Mutex
	requests []ScanRequest
}

// Enqueue adds a new scan request to the queue.
func (sq *ScanQueue) Enqueue(cidr, segment string, scanPorts bool) {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	sq.requests = append(sq.requests, ScanRequest{
		CIDR:        cidr,
		Segment:     segment,
		ScanPorts:   scanPorts,
		RequestedAt: time.Now(),
	})
}

// Drain returns all pending requests and clears the queue.
func (sq *ScanQueue) Drain() []ScanRequest {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	requests := sq.requests
	sq.requests = nil
	return requests
}
