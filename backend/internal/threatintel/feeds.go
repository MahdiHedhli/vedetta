package threatintel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FeedScheduler manages periodic downloads of threat intelligence feeds.
type FeedScheduler struct {
	db     *ThreatIntelDB
	client *http.Client
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewFeedScheduler creates a feed scheduler that will populate the threat DB.
func NewFeedScheduler(db *ThreatIntelDB) *FeedScheduler {
	return &FeedScheduler{
		db: db,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		done: make(chan struct{}),
	}
}

// Start begins all feed download goroutines on their configured intervals.
func (fs *FeedScheduler) Start() {
	log.Println("threatintel: feed scheduler starting")

	// Run all feeds immediately on startup
	go fs.runOnce()

	// URLhaus: every 5 minutes (small feed, changes frequently)
	fs.schedule("urlhaus", 5*time.Minute, fs.fetchURLhaus)

	// Feodo Tracker C2 IPs: every hour
	fs.schedule("feodotracker", 1*time.Hour, fs.fetchFeodoTracker)

	// SSLBL JA3 fingerprints: every 6 hours
	fs.schedule("sslbl", 6*time.Hour, fs.fetchSSLBL)

	// Indicator purge: every 12 hours
	fs.schedule("purge", 12*time.Hour, func() error {
		deleted, err := fs.db.PurgeExpired()
		if err != nil {
			return err
		}
		if deleted > 0 {
			log.Printf("threatintel: purged %d expired indicators", deleted)
		}
		return nil
	})
}

// Stop shuts down all feed goroutines.
func (fs *FeedScheduler) Stop() {
	close(fs.done)
	fs.wg.Wait()
	log.Println("threatintel: feed scheduler stopped")
}

func (fs *FeedScheduler) runOnce() {
	fs.fetchURLhaus()
	fs.fetchFeodoTracker()
	fs.fetchSSLBL()
}

func (fs *FeedScheduler) schedule(name string, interval time.Duration, fn func() error) {
	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := fn(); err != nil {
					log.Printf("threatintel: %s feed error: %v", name, err)
				}
			case <-fs.done:
				return
			}
		}
	}()
}

// fetchURLhaus downloads the abuse.ch URLhaus domain blocklist.
// Format: CSV with comment lines starting with #
// Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
// We extract domains from the URL column.
func (fs *FeedScheduler) fetchURLhaus() error {
	resp, err := fs.client.Get("https://urlhaus.abuse.ch/downloads/csv_recent/")
	if err != nil {
		return fmt.Errorf("urlhaus download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("urlhaus: HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	var indicators []Indicator
	now := time.Now().UTC()

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse CSV (simple split — URLhaus uses quoted CSV but domains don't contain commas)
		fields := splitCSV(line)
		if len(fields) < 7 {
			continue
		}

		url := unquote(fields[2])
		domain := extractDomain(url)
		if domain == "" {
			continue
		}

		tags := parseTags(unquote(fields[6]))

		indicators = append(indicators, Indicator{
			Value:      domain,
			Type:       "domain",
			Source:     "urlhaus",
			Confidence: 0.85,
			Tags:       append(tags, "malware_distribution"),
			FirstSeen:  now,
			LastSeen:   now,
			TTLHours:   168, // 7 days
		})
	}

	if len(indicators) > 0 {
		imported, err := fs.db.BulkImport(indicators)
		if err != nil {
			return fmt.Errorf("urlhaus import: %w", err)
		}
		log.Printf("threatintel: urlhaus imported %d/%d indicators", imported, len(indicators))
	}

	return nil
}

// fetchFeodoTracker downloads the Feodo Tracker C2 IP blocklist.
// Format: JSON array of objects with fields: ip_address, port, status, etc.
func (fs *FeedScheduler) fetchFeodoTracker() error {
	resp, err := fs.client.Get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")
	if err != nil {
		return fmt.Errorf("feodotracker download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feodotracker: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit
	if err != nil {
		return fmt.Errorf("feodotracker read: %w", err)
	}

	var entries []struct {
		IPAddress  string `json:"ip_address"`
		Port       int    `json:"dst_port"`
		Malware    string `json:"malware"`
		Status     string `json:"status"`
		FirstSeen  string `json:"first_seen"`
		LastOnline string `json:"last_online"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		return fmt.Errorf("feodotracker parse: %w", err)
	}

	now := time.Now().UTC()
	indicators := make([]Indicator, 0, len(entries))

	for _, e := range entries {
		if e.IPAddress == "" {
			continue
		}

		tags := []string{"c2"}
		if e.Malware != "" {
			tags = append(tags, strings.ToLower(e.Malware))
		}

		indicators = append(indicators, Indicator{
			Value:      e.IPAddress,
			Type:       "ipv4",
			Source:     "feodotracker",
			Confidence: 0.95,
			Tags:       tags,
			FirstSeen:  now,
			LastSeen:   now,
			TTLHours:   72, // 3 days (C2 IPs rotate faster)
		})
	}

	if len(indicators) > 0 {
		imported, err := fs.db.BulkImport(indicators)
		if err != nil {
			return fmt.Errorf("feodotracker import: %w", err)
		}
		log.Printf("threatintel: feodotracker imported %d/%d indicators", imported, len(indicators))
	}

	return nil
}

// fetchSSLBL downloads the abuse.ch SSL Blacklist JA3 fingerprints.
// Format: CSV with comment lines starting with #
// Columns: listing_date, sha1, listing_reason
func (fs *FeedScheduler) fetchSSLBL() error {
	resp, err := fs.client.Get("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv")
	if err != nil {
		return fmt.Errorf("sslbl download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sslbl: HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 5<<20))
	var indicators []Indicator
	now := time.Now().UTC()

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := splitCSV(line)
		if len(fields) < 3 {
			continue
		}

		ja3 := unquote(fields[1])
		if len(ja3) != 32 { // MD5 hash length
			continue
		}
		reason := unquote(fields[2])

		tags := []string{"malicious_tls"}
		if strings.Contains(strings.ToLower(reason), "c2") || strings.Contains(strings.ToLower(reason), "c&c") {
			tags = append(tags, "c2")
		}

		indicators = append(indicators, Indicator{
			Value:      ja3,
			Type:       "ja3",
			Source:     "sslbl",
			Confidence: 0.90,
			Tags:       tags,
			FirstSeen:  now,
			LastSeen:   now,
			TTLHours:   336, // 14 days (JA3 fingerprints are more stable)
		})
	}

	if len(indicators) > 0 {
		imported, err := fs.db.BulkImport(indicators)
		if err != nil {
			return fmt.Errorf("sslbl import: %w", err)
		}
		log.Printf("threatintel: sslbl imported %d/%d indicators", imported, len(indicators))
	}

	return nil
}

// --- Helpers ---

// splitCSV does a simple comma split respecting double-quoted fields.
func splitCSV(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())
	return fields
}

func unquote(s string) string {
	return strings.Trim(strings.TrimSpace(s), "\"")
}

// extractDomain pulls the hostname from a URL string.
func extractDomain(rawURL string) string {
	// Strip protocol
	u := rawURL
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// Strip path
	if idx := strings.IndexAny(u, "/:?#"); idx >= 0 {
		u = u[:idx]
	}
	// Strip port
	if idx := strings.LastIndex(u, ":"); idx >= 0 {
		u = u[:idx]
	}
	return strings.ToLower(strings.TrimSpace(u))
}

// parseTags splits a tag string (space or comma separated) into a slice.
func parseTags(s string) []string {
	s = strings.ReplaceAll(s, ",", " ")
	parts := strings.Fields(s)
	var tags []string
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			tags = append(tags, p)
		}
	}
	return tags
}
