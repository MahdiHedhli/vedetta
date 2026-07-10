package store

import (
	"testing"
)

// Issue #7: a DB upgraded from a build that predates write-time scan-target
// validation can carry a planted 0.0.0.0/0 target. ScrubInvalidScanTargets must
// disable such rows at startup so they are never served to the root sensor, while
// leaving legitimate targets enabled.
func TestScrubInvalidScanTargets(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// CreateScanTarget does not validate (validation lives at the API boundary), so
	// it faithfully simulates a pre-upgrade row that bypassed validation.
	good, err := db.CreateScanTarget("lan", "192.168.1.0/24", "default", true, false, "")
	if err != nil {
		t.Fatalf("create good target: %v", err)
	}
	bad, err := db.CreateScanTarget("planted", "0.0.0.0/0", "default", true, false, "")
	if err != nil {
		t.Fatalf("create bad target: %v", err)
	}

	n, err := db.ScrubInvalidScanTargets()
	if err != nil {
		t.Fatalf("scrub: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 target disabled, got %d", n)
	}

	// The planted /0 must no longer be enabled (so it can't be served)...
	enabled, err := db.GetEnabledScanTargets()
	if err != nil {
		t.Fatalf("get enabled: %v", err)
	}
	for _, tg := range enabled {
		if tg.TargetID == bad.TargetID {
			t.Fatalf("planted 0.0.0.0/0 target %s is still enabled after scrub", bad.TargetID)
		}
	}
	// ...while the legitimate target stays enabled.
	foundGood := false
	for _, tg := range enabled {
		if tg.TargetID == good.TargetID {
			foundGood = true
		}
	}
	if !foundGood {
		t.Fatalf("legitimate target %s was incorrectly disabled", good.TargetID)
	}

	// Idempotent: a second run disables nothing.
	if n2, err := db.ScrubInvalidScanTargets(); err != nil || n2 != 0 {
		t.Fatalf("second scrub expected (0, nil), got (%d, %v)", n2, err)
	}
}
