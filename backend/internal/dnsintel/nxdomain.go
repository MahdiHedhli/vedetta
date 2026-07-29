package dnsintel

import (
	"sort"
	"sync"
	"time"
)

// NXDomainBurstDetector correlates DGA-shaped domains with a burst of
// NXDOMAIN responses from one device. A random-looking name on its own is
// common in legitimate telemetry and CDN traffic; several distinct failures in
// a short window are materially stronger evidence of a DGA fallback cycle.
//
// State is intentionally bounded and short-lived. It is behavioural evidence,
// not a durable reputation database, and is reset safely on Core restart.
type NXDomainBurstDetector struct {
	mu      sync.Mutex
	entries map[string]*nxdomainEntry

	Window             time.Duration
	MinDistinctDomains int
	EntryTTL           time.Duration
}

type nxdomainEntry struct {
	observations []nxdomainObservation
	lastSeen     time.Time
}

type nxdomainObservation struct {
	domain string
	at     time.Time
}

// NXDomainBurstResult describes the corroborating DGA/NXDOMAIN evidence for a
// source in the current window.
type NXDomainBurstResult struct {
	IsBurst         bool
	DistinctDomains int
	Window          time.Duration
}

func NewNXDomainBurstDetector() *NXDomainBurstDetector {
	return &NXDomainBurstDetector{
		entries:            make(map[string]*nxdomainEntry),
		Window:             10 * time.Minute,
		MinDistinctDomains: 5,
		EntryTTL:           30 * time.Minute,
	}
}

// RecordCandidate records one DGA-shaped NXDOMAIN response and returns true
// only after enough distinct domains from the same device appear in the rolling
// window. Callers must have already verified that the response code is
// NXDOMAIN; this method deliberately has no DNS parsing responsibility.
func (d *NXDomainBurstDetector) RecordCandidate(sourceHash, domain string, at time.Time) NXDomainBurstResult {
	if d == nil || sourceHash == "" || domain == "" {
		return NXDomainBurstResult{}
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	at = at.UTC()

	d.mu.Lock()
	defer d.mu.Unlock()
	entry := d.entries[sourceHash]
	if entry == nil {
		entry = &nxdomainEntry{}
		d.entries[sourceHash] = entry
	}
	entry.observations = append(entry.observations, nxdomainObservation{domain: domain, at: at})
	sort.SliceStable(entry.observations, func(i, j int) bool { return entry.observations[i].at.Before(entry.observations[j].at) })
	reference := at
	if entry.lastSeen.After(reference) {
		reference = entry.lastSeen
	}
	cutoff := reference.Add(-d.Window)
	first := 0
	for first < len(entry.observations) && entry.observations[first].at.Before(cutoff) {
		first++
	}
	entry.observations = append([]nxdomainObservation(nil), entry.observations[first:]...)
	entry.lastSeen = reference

	distinct := make(map[string]struct{}, len(entry.observations))
	for _, observation := range entry.observations {
		distinct[observation.domain] = struct{}{}
	}
	count := len(distinct)
	return NXDomainBurstResult{
		IsBurst:         count >= d.MinDistinctDomains,
		DistinctDomains: count,
		Window:          d.Window,
	}
}

func (d *NXDomainBurstDetector) EvictStale(now time.Time) int {
	if d == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	evicted := 0
	for key, entry := range d.entries {
		if now.Sub(entry.lastSeen) > d.EntryTTL {
			delete(d.entries, key)
			evicted++
		}
	}
	return evicted
}

func (d *NXDomainBurstDetector) EntryCount() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}
