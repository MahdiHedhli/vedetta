package threatintel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCommunityFeedURL = "https://feed.vedettas.com"
	urlhausHostfileURL      = "https://urlhaus.abuse.ch/downloads/hostfile/"
	feodoTrackerURL         = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
	maxURLhausBytes         = 10 << 20
	maxFeodoTrackerBytes    = 5 << 20
)

type feedRefresh func() (int, error)

// FeedHealth is the operator-facing state of one threat-intelligence source.
// It deliberately reports freshness and item counts, not only whether the
// scheduler goroutine is alive.
type FeedHealth struct {
	Name        string     `json:"name"`
	State       string     `json:"state"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	ItemCount   int        `json:"item_count"`
	LastError   string     `json:"last_error,omitempty"`

	interval time.Duration
}

// FeedScheduler manages periodic downloads of threat intelligence feeds.
type FeedScheduler struct {
	db               *ThreatIntelDB
	client           *http.Client
	communityBaseURL string
	communityEnabled bool
	done             chan struct{}
	wg               sync.WaitGroup

	healthMu sync.RWMutex
	health   map[string]FeedHealth
}

// NewFeedScheduler creates a feed scheduler that will populate the threat DB.
func NewFeedScheduler(db *ThreatIntelDB) *FeedScheduler {
	return NewFeedSchedulerConfigured(db, DefaultCommunityFeedURL, true)
}

// NewFeedSchedulerWithCommunity creates a scheduler using the same public base
// URL as telemetry contribution. The public feed is advisory-only downstream;
// local curated feeds remain independently represented and authoritative.
func NewFeedSchedulerWithCommunity(db *ThreatIntelDB, communityBaseURL string) *FeedScheduler {
	return NewFeedSchedulerConfigured(db, communityBaseURL, true)
}

// NewFeedSchedulerConfigured supports fully offline installations. Disabling
// consumption removes the community source from scheduling and health rather
// than reporting a deliberate operator choice as an error.
func NewFeedSchedulerConfigured(db *ThreatIntelDB, communityBaseURL string, communityEnabled bool) *FeedScheduler {
	communityBaseURL = strings.TrimSpace(communityBaseURL)
	if communityBaseURL == "" {
		communityBaseURL = DefaultCommunityFeedURL
	}
	fs := &FeedScheduler{
		db:               db,
		communityBaseURL: communityBaseURL,
		communityEnabled: communityEnabled,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		done: make(chan struct{}),
		health: map[string]FeedHealth{
			"urlhaus":      {Name: "urlhaus", State: "initializing", interval: 5 * time.Minute},
			"feodotracker": {Name: "feodotracker", State: "initializing", interval: time.Hour},
		},
	}
	if communityEnabled {
		fs.health[communityFeedSource] = FeedHealth{Name: communityFeedSource, State: "initializing", interval: 15 * time.Minute}
	}
	return fs
}

// Start begins all feed download goroutines on their configured intervals.
func (fs *FeedScheduler) Start() {
	log.Println("threatintel: feed scheduler starting")

	// Run all feeds immediately on startup
	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		fs.runOnce()
	}()

	// URLhaus: every 5 minutes (small feed, changes frequently)
	fs.schedule("urlhaus", 5*time.Minute, fs.fetchURLhaus)

	// Feodo Tracker C2 IPs: every hour
	fs.schedule("feodotracker", 1*time.Hour, fs.fetchFeodoTracker)

	// Vedetta community consensus: public, advisory-only, complete snapshot.
	if fs.communityEnabled {
		fs.schedule(communityFeedSource, 15*time.Minute, fs.fetchCommunity)
	}

	// Indicator purge: every 12 hours
	fs.scheduleJob("purge", 12*time.Hour, func() error {
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

// scheduleJob runs maintenance that is not itself a threat feed. Keeping it
// separate prevents jobs such as purge from appearing in operator feed health.
func (fs *FeedScheduler) scheduleJob(name string, interval time.Duration, fn func() error) {
	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := fn(); err != nil {
					log.Printf("threatintel: %s job error: %v", name, err)
				}
			case <-fs.done:
				return
			}
		}
	}()
}

// Stop shuts down all feed goroutines.
func (fs *FeedScheduler) Stop() {
	close(fs.done)
	fs.wg.Wait()
	log.Println("threatintel: feed scheduler stopped")
}

func (fs *FeedScheduler) runOnce() {
	var wg sync.WaitGroup
	feeds := []struct {
		name string
		fn   feedRefresh
	}{
		{name: "urlhaus", fn: fs.fetchURLhaus},
		{name: "feodotracker", fn: fs.fetchFeodoTracker},
	}
	if fs.communityEnabled {
		feeds = append(feeds, struct {
			name string
			fn   feedRefresh
		}{name: communityFeedSource, fn: fs.fetchCommunity})
	}
	for _, feed := range feeds {
		feed := feed
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fs.runFeed(feed.name, feed.fn); err != nil {
				log.Printf("threatintel: %s feed error: %v", feed.name, err)
			}
		}()
	}
	wg.Wait()
}

func (fs *FeedScheduler) fetchCommunity() (int, error) {
	imported, err := ImportCommunityFeed(fs.db, fs.client, fs.communityBaseURL)
	if err != nil {
		return 0, err
	}
	log.Printf("threatintel: community snapshot contains %d locally matchable indicators", imported)
	return imported, nil
}

func (fs *FeedScheduler) schedule(name string, interval time.Duration, fn feedRefresh) {
	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := fs.runFeed(name, fn); err != nil {
					log.Printf("threatintel: %s feed error: %v", name, err)
				}
			case <-fs.done:
				return
			}
		}
	}()
}

// Status returns a stable snapshot suitable for the detection-health API.
// A source is stale after two missed refresh intervals. A failed refresh after
// the last success is reported as an error even if older indicators remain in
// the local database.
func (fs *FeedScheduler) Status() []FeedHealth {
	fs.healthMu.RLock()
	health := make([]FeedHealth, 0, len(fs.health))
	for _, status := range fs.health {
		health = append(health, status)
	}
	fs.healthMu.RUnlock()

	now := time.Now().UTC()
	for i := range health {
		status := &health[i]
		switch {
		case status.LastError != "":
			status.State = "error"
		case status.LastSuccess == nil:
			status.State = "initializing"
		case status.interval > 0 && now.Sub(*status.LastSuccess) > 2*status.interval:
			status.State = "stale"
		default:
			status.State = "healthy"
		}
	}
	sort.Slice(health, func(i, j int) bool { return health[i].Name < health[j].Name })
	return health
}

func (fs *FeedScheduler) runFeed(name string, fn feedRefresh) error {
	attempted := time.Now().UTC()
	fs.healthMu.Lock()
	status := fs.health[name]
	status.Name = name
	status.LastAttempt = &attempted
	status.LastError = ""
	fs.health[name] = status
	fs.healthMu.Unlock()

	itemCount, err := fn()
	if err != nil {
		fs.recordFeedError(name, err)
		return err
	}
	if itemCount < 0 {
		err = fmt.Errorf("refresh returned invalid item count %d", itemCount)
		fs.recordFeedError(name, err)
		return err
	}

	succeeded := time.Now().UTC()
	fs.healthMu.Lock()
	status = fs.health[name]
	status.State = "healthy"
	status.LastSuccess = &succeeded
	status.ItemCount = itemCount
	status.LastError = ""
	fs.health[name] = status
	fs.healthMu.Unlock()
	return nil
}

func (fs *FeedScheduler) recordFeedError(name string, err error) {
	fs.healthMu.Lock()
	status := fs.health[name]
	status.Name = name
	status.State = "error"
	status.LastError = err.Error()
	fs.health[name] = status
	fs.healthMu.Unlock()
}

// fetchURLhaus downloads URLhaus's DNS-oriented host file. URLhaus documents
// this artifact specifically for hostname blocking, limits it to active/recent
// malware hosts, and excludes Tranco Top 1M hostnames to reduce false positives:
// https://urlhaus.abuse.ch/api/#hostfile
//
// Do not derive domain IOCs from URLhaus's URL-level CSV. A malicious path on a
// shared host does not make the entire hostname a high-confidence DNS IOC.
func (fs *FeedScheduler) fetchURLhaus() (int, error) {
	resp, err := fs.client.Get(urlhausHostfileURL)
	if err != nil {
		return 0, fmt.Errorf("urlhaus download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("urlhaus: HTTP %d", resp.StatusCode)
	}

	body, err := readBounded(resp.Body, maxURLhausBytes)
	if err != nil {
		return 0, fmt.Errorf("urlhaus read: %w", err)
	}
	indicators, err := parseURLhausHostfile(body, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("urlhaus parse: %w", err)
	}

	imported, err := fs.db.ReplaceSource("urlhaus", indicators)
	if err != nil {
		return 0, fmt.Errorf("urlhaus import: %w", err)
	}
	log.Printf("threatintel: urlhaus snapshot contains %d indicators", imported)
	return imported, nil
}

// fetchFeodoTracker downloads the Feodo Tracker C2 IP blocklist.
// Format: JSON array of objects with fields: ip_address, port, status, etc.
func (fs *FeedScheduler) fetchFeodoTracker() (int, error) {
	resp, err := fs.client.Get(feodoTrackerURL)
	if err != nil {
		return 0, fmt.Errorf("feodotracker download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("feodotracker: HTTP %d", resp.StatusCode)
	}

	body, err := readBounded(resp.Body, maxFeodoTrackerBytes)
	if err != nil {
		return 0, fmt.Errorf("feodotracker read: %w", err)
	}
	indicators, err := parseFeodoTracker(body, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("feodotracker parse: %w", err)
	}

	imported, err := fs.db.ReplaceSource("feodotracker", indicators)
	if err != nil {
		return 0, fmt.Errorf("feodotracker import: %w", err)
	}
	log.Printf("threatintel: feodotracker snapshot contains %d indicators", imported)
	return imported, nil
}

func parseURLhausHostfile(body []byte, now time.Time) ([]Indicator, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	// A host-file row is tiny. A larger token indicates corruption rather than a
	// legitimate indicator; retaining Scanner's error is important for health.
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	sawHeader := false
	sawFooter := false
	declaredEntries := -1
	parsedEntries := 0
	lineNumber := 0
	unique := make(map[string]Indicator)

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if sawFooter {
			return nil, fmt.Errorf("line %d follows entry-count footer", lineNumber)
		}
		if strings.HasPrefix(line, "#") {
			if strings.Contains(line, "abuse.ch URLhaus Host file") {
				sawHeader = true
			}
			if value, ok := strings.CutPrefix(line, "# Number of entries:"); ok {
				count, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil || count < 0 {
					return nil, fmt.Errorf("line %d has invalid entry count", lineNumber)
				}
				declaredEntries = count
				sawFooter = true
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d is not a two-column host-file row", lineNumber)
		}
		sink := net.ParseIP(fields[0])
		if sink == nil || (!sink.IsLoopback() && !sink.IsUnspecified()) {
			return nil, fmt.Errorf("line %d has invalid host-file sink address", lineNumber)
		}
		domain, err := normalizeDNSHostname(fields[1])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		parsedEntries++
		unique[domain] = Indicator{
			Value:      domain,
			Type:       "domain",
			Source:     "urlhaus",
			Confidence: 0.85,
			Tags:       []string{"malware_distribution"},
			FirstSeen:  now,
			LastSeen:   now,
			TTLHours:   168,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if !sawHeader {
		return nil, fmt.Errorf("missing URLhaus host-file header")
	}
	if declaredEntries < 0 {
		return nil, fmt.Errorf("missing entry-count footer (possibly truncated)")
	}
	if declaredEntries != parsedEntries {
		return nil, fmt.Errorf("entry-count footer says %d, parsed %d", declaredEntries, parsedEntries)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("feed contains zero valid domain indicators")
	}

	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	indicators := make([]Indicator, 0, len(domains))
	for _, domain := range domains {
		indicators = append(indicators, unique[domain])
	}
	return indicators, nil
}

func normalizeDNSHostname(value string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return "", fmt.Errorf("invalid domain hostname %q", value)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("invalid domain hostname %q", value)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain hostname %q", value)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("invalid domain hostname %q", value)
			}
		}
	}
	return host, nil
}

func parseFeodoTracker(body []byte, now time.Time) ([]Indicator, error) {

	var entries []struct {
		IPAddress string `json:"ip_address"`
		Malware   string `json:"malware"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("feed contains zero entries")
	}
	indicators := make([]Indicator, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))

	for i, e := range entries {
		ip := net.ParseIP(strings.TrimSpace(e.IPAddress))
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("entry %d has invalid IPv4 address %q", i, e.IPAddress)
		}
		value := ip.To4().String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}

		tags := []string{"c2"}
		if e.Malware != "" {
			tags = append(tags, strings.ToLower(e.Malware))
		}

		indicators = append(indicators, Indicator{
			Value:      value,
			Type:       "ipv4",
			Source:     "feodotracker",
			Confidence: 0.95,
			Tags:       tags,
			FirstSeen:  now,
			LastSeen:   now,
			TTLHours:   72, // 3 days (C2 IPs rotate faster)
		})
	}
	if len(indicators) == 0 {
		return nil, fmt.Errorf("feed contains zero valid IPv4 indicators")
	}
	return indicators, nil
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("invalid byte limit %d", maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d-byte limit", maxBytes)
	}
	return body, nil
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
