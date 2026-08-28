package threatintel

import (
	"testing"
	"time"
)

func TestLoadQTFYAdvisoryImportsExactCurrentIndicators(t *testing.T) {
	db := testThreatDB(t)
	loaded, err := loadQTFYAdvisoryAt(db, time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("load QTFY advisory: %v", err)
	}
	if loaded != len(qtfyAdvisoryEntries) {
		t.Fatalf("loaded %d entries, want %d", loaded, len(qtfyAdvisoryEntries))
	}

	for _, value := range []string{"securelink.qtproxy.xyz", "1.32.216.171", "27.124.24.220"} {
		result := db.Lookup(value)
		if !result.Found || result.Indicator == nil {
			t.Fatalf("expected exact IOC %q to be present", value)
		}
		if result.Indicator.Source != qtfyAdvisorySource || result.Confidence != 0.90 {
			t.Fatalf("IOC %q provenance = %#v", value, result.Indicator)
		}
	}

	if result := db.Lookup("subdomain.qtproxy.xyz"); result.Found {
		t.Fatalf("advisory domains must not become wildcard indicators: %#v", result.Indicator)
	}
}

func TestLoadQTFYAdvisoryReplacesOnlyItsOwnSnapshot(t *testing.T) {
	db := testThreatDB(t)
	if _, err := db.BulkImport([]Indicator{{
		Value: "unrelated.example", Type: "domain", Source: "fixture", Confidence: 0.9,
		LastSeen: time.Now().UTC(), TTLHours: 24,
	}}); err != nil {
		t.Fatalf("seed unrelated indicator: %v", err)
	}
	if _, err := loadQTFYAdvisoryAt(db, time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if _, err := loadQTFYAdvisoryAt(db, time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("replacement load: %v", err)
	}
	if got := db.Lookup("unrelated.example"); !got.Found {
		t.Fatal("replacing the advisory snapshot removed an unrelated source")
	}
}
