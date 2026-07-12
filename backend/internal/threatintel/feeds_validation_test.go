package threatintel

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const validURLhausHostfile = `################################################################
# abuse.ch URLhaus Host file
# Last updated: 2026-07-12 15:59:29 (UTC)
################################################################
127.0.0.1	evil-download.example
0.0.0.0	payload.badzone.example
# Number of entries: 2
`

func TestParseURLhausHostfileAcceptsOnlyDNSHostfileRows(t *testing.T) {
	now := time.Date(2026, 7, 12, 16, 0, 0, 0, time.UTC)
	indicators, err := parseURLhausHostfile([]byte(validURLhausHostfile), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(indicators) != 2 {
		t.Fatalf("indicators = %d, want 2", len(indicators))
	}
	if indicators[0].Value != "evil-download.example" || indicators[1].Value != "payload.badzone.example" {
		t.Fatalf("unexpected indicators: %+v", indicators)
	}
	for _, indicator := range indicators {
		if indicator.Type != "domain" || indicator.Source != "urlhaus" || indicator.Confidence != 0.85 {
			t.Fatalf("unexpected indicator semantics: %+v", indicator)
		}
	}

	// The old URL-level CSV is deliberately not accepted. Extracting the host
	// from this row would incorrectly condemn a shared hosting domain based on
	// one malicious path.
	csv := "# abuse.ch URLhaus Host file\n1,2026-07-12,https://downloads.example/one-malicious-file.exe,online\n# Number of entries: 1\n"
	if _, err := parseURLhausHostfile([]byte(csv), now); err == nil {
		t.Fatal("URL-level CSV unexpectedly accepted as a domain feed")
	}
}

func TestParseURLhausHostfileRejectsMalformedTruncatedAndEmptyResponses(t *testing.T) {
	now := time.Now().UTC()
	longLine := strings.Repeat("x", 300*1024)
	tests := []struct {
		name string
		body string
	}{
		{name: "empty"},
		{name: "missing footer", body: "# abuse.ch URLhaus Host file\n127.0.0.1 evil.example\n"},
		{name: "footer mismatch", body: "# abuse.ch URLhaus Host file\n127.0.0.1 evil.example\n# Number of entries: 2\n"},
		{name: "zero valid", body: "# abuse.ch URLhaus Host file\n# Number of entries: 0\n"},
		{name: "invalid domain", body: "# abuse.ch URLhaus Host file\n127.0.0.1 bad_host.example\n# Number of entries: 1\n"},
		{name: "non sink address", body: "# abuse.ch URLhaus Host file\n192.0.2.1 evil.example\n# Number of entries: 1\n"},
		{name: "scanner token too large", body: "# abuse.ch URLhaus Host file\n" + longLine + "\n# Number of entries: 1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseURLhausHostfile([]byte(tt.body), now); err == nil {
				t.Fatal("parse succeeded, want validation error")
			}
		})
	}
}

func TestParseFeodoTrackerRejectsMalformedTruncatedAndEmptyResponses(t *testing.T) {
	now := time.Now().UTC()
	valid := `[{"ip_address":"198.51.100.40","malware":"Emotet"},{"ip_address":"198.51.100.40","malware":"Emotet"}]`
	indicators, err := parseFeodoTracker([]byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(indicators) != 1 || indicators[0].Value != "198.51.100.40" {
		t.Fatalf("unexpected indicators: %+v", indicators)
	}

	for name, body := range map[string]string{
		"empty array":  `[]`,
		"invalid ipv4": `[{"ip_address":"not-an-ip"}]`,
		"truncated":    `[{"ip_address":"198.51.100.40"}`,
		"trailing json": `[{"ip_address":"198.51.100.40"}]
{"unexpected":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFeodoTracker([]byte(body), now); err == nil {
				t.Fatal("parse succeeded, want validation error")
			}
		})
	}
}

func TestURLhausRefreshReplacesSnapshotAndReportsCurrentCount(t *testing.T) {
	db := testThreatDB(t)
	if _, err := db.BulkImport([]Indicator{
		{Value: "shared-downloads.example", Type: "domain", Source: "urlhaus", Confidence: 0.85},
		{Value: "stale.example", Type: "domain", Source: "urlhaus", Confidence: 0.85},
	}); err != nil {
		t.Fatal(err)
	}

	fs := NewFeedScheduler(db)
	fs.client = feedTestClient(http.StatusOK, validURLhausHostfile)
	if err := fs.runFeed("urlhaus", fs.fetchURLhaus); err != nil {
		t.Fatal(err)
	}
	status := feedStatusByName(fs.Status(), "urlhaus")
	if status.State != "healthy" || status.ItemCount != 2 {
		t.Fatalf("health = %+v, want healthy current count 2", status)
	}
	if db.Lookup("shared-downloads.example").Found || db.Lookup("stale.example").Found {
		t.Fatal("disappeared URLhaus rows survived a complete snapshot refresh")
	}
	if !db.Lookup("evil-download.example").Found {
		t.Fatal("DNS-safe URLhaus hostname was not imported")
	}
}

func TestMalformedRefreshFailsHealthWithoutReplacingLastGoodSnapshot(t *testing.T) {
	db := testThreatDB(t)
	if _, err := db.ReplaceSource("urlhaus", []Indicator{{
		Value: "last-good.example", Type: "domain", Source: "urlhaus", Confidence: 0.85,
	}}); err != nil {
		t.Fatal(err)
	}

	fs := NewFeedScheduler(db)
	fs.client = feedTestClient(http.StatusOK, "# abuse.ch URLhaus Host file\n127.0.0.1 partial.example\n")
	if err := fs.runFeed("urlhaus", fs.fetchURLhaus); err == nil {
		t.Fatal("malformed refresh succeeded")
	}
	status := feedStatusByName(fs.Status(), "urlhaus")
	if status.State != "error" || status.LastError == "" || status.LastSuccess != nil {
		t.Fatalf("health = %+v, want an initial refresh error", status)
	}
	if !db.Lookup("last-good.example").Found {
		t.Fatal("failed refresh replaced the last good snapshot")
	}
}

func TestFeodoRefreshReportsCurrentCountAndRejectsZeroValidSnapshot(t *testing.T) {
	db := testThreatDB(t)
	if _, err := db.ReplaceSource("feodotracker", []Indicator{{
		Value: "198.51.100.10", Type: "ipv4", Source: "feodotracker", Confidence: 0.95,
	}}); err != nil {
		t.Fatal(err)
	}

	fs := NewFeedScheduler(db)
	fs.client = feedTestClient(http.StatusOK, `[{"ip_address":"198.51.100.20","malware":"QakBot"},{"ip_address":"198.51.100.21","malware":"Emotet"}]`)
	if err := fs.runFeed("feodotracker", fs.fetchFeodoTracker); err != nil {
		t.Fatal(err)
	}
	status := feedStatusByName(fs.Status(), "feodotracker")
	if status.State != "healthy" || status.ItemCount != 2 {
		t.Fatalf("health = %+v, want healthy current count 2", status)
	}
	if db.Lookup("198.51.100.10").Found || !db.Lookup("198.51.100.20").Found {
		t.Fatal("Feodo complete snapshot was not replaced")
	}

	lastSuccess := status.LastSuccess
	fs.client = feedTestClient(http.StatusOK, `[]`)
	if err := fs.runFeed("feodotracker", fs.fetchFeodoTracker); err == nil {
		t.Fatal("zero-entry Feodo snapshot succeeded")
	}
	status = feedStatusByName(fs.Status(), "feodotracker")
	if status.State != "error" || status.ItemCount != 2 || status.LastSuccess == nil || !status.LastSuccess.Equal(*lastSuccess) {
		t.Fatalf("health after rejected refresh = %+v", status)
	}
	if !db.Lookup("198.51.100.20").Found {
		t.Fatal("rejected Feodo refresh replaced the last good snapshot")
	}
}

func TestReadBoundedPropagatesReadErrorsAndRejectsOversize(t *testing.T) {
	wantErr := errors.New("truncated response")
	if _, err := readBounded(erroringReader{err: wantErr}, 32); !errors.Is(err, wantErr) {
		t.Fatalf("read error = %v, want %v", err, wantErr)
	}
	if _, err := readBounded(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response accepted")
	}
}

type feedRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn feedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func feedTestClient(status int, body string) *http.Client {
	return &http.Client{Transport: feedRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
}

type erroringReader struct {
	err error
}

func (r erroringReader) Read([]byte) (int, error) {
	return 0, r.err
}
