package api

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// TestWriteEventsCSV_FormulaInjectionAndQuoting is the GHSA-45j4 regression: the CSV
// export must (1) neutralize spreadsheet formula injection by prefixing any cell
// starting with = + - @ (or tab/CR) with a single quote, and (2) correctly quote
// values containing commas, quotes, and newlines via encoding/csv.
func TestWriteEventsCSV_FormulaInjectionAndQuoting(t *testing.T) {
	events := []models.Event{
		{
			EventID:    "evt-1",
			Timestamp:  time.Unix(1700000000, 0).UTC(),
			EventType:  "dns_query",
			SourceHash: "sha256:x",
			Domain:     "=CMD()|'/c calc'!A1",             // formula injection attempt
			ThreatDesc: "malware, \"evil\", line1\nline2", // commas, quotes, newline
			DNSSource:  "@SUM(1+1)",                       // another formula lead char
			Outcome:    "observed",
		},
	}

	var buf bytes.Buffer
	writeEventsCSV(&buf, events)
	out := buf.String()

	// The raw formula must not appear unescaped anywhere as a cell start.
	if strings.Contains(out, ",=CMD()") {
		t.Fatalf("formula cell was not neutralized:\n%s", out)
	}

	// Parse it back with a strict CSV reader: this proves quoting is well-formed
	// (a broken serializer would fail to parse or mis-split the malicious cell).
	r := csv.NewReader(strings.NewReader(out))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, out)
	}
	if len(records) != 2 {
		t.Fatalf("expected header + 1 row, got %d records", len(records))
	}

	header, row := records[0], records[1]
	col := func(name string) string {
		for i, h := range header {
			if h == name {
				return row[i]
			}
		}
		t.Fatalf("column %q not found in header", name)
		return ""
	}

	if got := col("domain"); !strings.HasPrefix(got, "'=CMD()") {
		t.Fatalf("domain cell not defanged with leading quote: %q", got)
	}
	if got := col("dns_source"); !strings.HasPrefix(got, "'@SUM") {
		t.Fatalf("dns_source cell not defanged with leading quote: %q", got)
	}
	if got := col("outcome"); got != "observed" {
		t.Fatalf("outcome missing from CSV: %q", got)
	}
	// The comma/quote/newline field must survive round-trip intact.
	if got := col("threat_desc"); got != "malware, \"evil\", line1\nline2" {
		t.Fatalf("threat_desc mangled by CSV serializer: %q", got)
	}
}
