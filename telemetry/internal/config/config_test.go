package config

import (
	"testing"
	"time"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(envFrom(nil))
	if err != nil {
		t.Fatalf("Load with empty env: %v", err)
	}
	if c.OptIn {
		t.Errorf("OptIn should default to false")
	}
	if c.DryRun {
		t.Errorf("DryRun should default to false")
	}
	if c.ThreatNetworkURL != defaultThreatNetworkURL {
		t.Errorf("ThreatNetworkURL = %q", c.ThreatNetworkURL)
	}
	if c.CoreURL != defaultCoreURL {
		t.Errorf("CoreURL = %q", c.CoreURL)
	}
	if c.StateDir != defaultStateDir {
		t.Errorf("StateDir = %q", c.StateDir)
	}
	if c.StatusAddr != defaultStatusAddr {
		t.Errorf("StatusAddr = %q", c.StatusAddr)
	}
	if c.TickInterval != defaultTickInterval {
		t.Errorf("TickInterval = %v", c.TickInterval)
	}
	if c.CandidateMinScore != defaultCandidateScore {
		t.Errorf("CandidateMinScore = %v", c.CandidateMinScore)
	}
	if c.MaxBatchItems != defaultMaxBatchItems {
		t.Errorf("MaxBatchItems = %v", c.MaxBatchItems)
	}
}

func TestLoadOverrides(t *testing.T) {
	c, err := Load(envFrom(map[string]string{
		"VEDETTA_TELEMETRY_OPTIN":                "true",
		"VEDETTA_TELEMETRY_DRYRUN":               "true",
		"VEDETTA_CORE_TOKEN":                     "core-token-example",
		"VEDETTA_THREAT_NETWORK_URL":             "https://tn.example",
		"VEDETTA_CORE_URL":                       "https://core.example",
		"VEDETTA_TELEMETRY_STATE_DIR":            "/data/state",
		"VEDETTA_TELEMETRY_STATUS_ADDR":          "127.0.0.1:7000",
		"VEDETTA_TELEMETRY_TICK_INTERVAL":        "5m",
		"VEDETTA_TELEMETRY_CANDIDATE_MIN_SCORE":  "0.9",
		"VEDETTA_TELEMETRY_BEHAVIOR_MIN_SCORE":   "0.6",
		"VEDETTA_TELEMETRY_READ_CAP":             "1000",
		"VEDETTA_TELEMETRY_MAX_BATCH_ITEMS":      "100",
		"VEDETTA_TELEMETRY_MAX_BATCHES_PER_TICK": "2",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.OptIn || !c.DryRun {
		t.Errorf("OptIn/DryRun not set")
	}
	if c.TickInterval != 5*time.Minute {
		t.Errorf("TickInterval = %v", c.TickInterval)
	}
	if c.CandidateMinScore != 0.9 || c.BehaviorMinScore != 0.6 {
		t.Errorf("thresholds = %v/%v", c.CandidateMinScore, c.BehaviorMinScore)
	}
	if c.ReadCapPerTick != 1000 || c.MaxBatchItems != 100 || c.MaxBatchesTick != 2 {
		t.Errorf("caps = %d/%d/%d", c.ReadCapPerTick, c.MaxBatchItems, c.MaxBatchesTick)
	}
}

func TestOptInRequiresToken(t *testing.T) {
	_, err := Load(envFrom(map[string]string{
		"VEDETTA_TELEMETRY_OPTIN": "true",
	}))
	if err == nil {
		t.Fatalf("expected error when opted in without CoreToken")
	}
}

func TestOptInOffNeverErrors(t *testing.T) {
	// Even with a garbage tick interval, off means off — but interval parse
	// happens before the opt-in check, so use a value that only matters when on.
	c, err := Load(envFrom(map[string]string{
		"VEDETTA_TELEMETRY_CANDIDATE_MIN_SCORE": "5.0", // out of range but ignored while off
	}))
	if err != nil {
		t.Fatalf("off should not error on out-of-range threshold: %v", err)
	}
	if c.OptIn {
		t.Errorf("should be off")
	}
}

func TestExactStringOptIn(t *testing.T) {
	for _, v := range []string{"TRUE", "1", "yes", "True", ""} {
		c, _ := Load(envFrom(map[string]string{"VEDETTA_TELEMETRY_OPTIN": v}))
		if c.OptIn {
			t.Errorf("value %q should not enable opt-in", v)
		}
	}
}

func TestInvalidTickInterval(t *testing.T) {
	if _, err := Load(envFrom(map[string]string{"VEDETTA_TELEMETRY_TICK_INTERVAL": "notaduration"})); err == nil {
		t.Fatalf("expected error for invalid tick interval")
	}
}
