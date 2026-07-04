// Package config parses telemetry daemon configuration from the environment.
//
// The single most important behavior: unless VEDETTA_TELEMETRY_OPTIN is exactly
// "true", the daemon is OFF. OptIn() is the gate the rest of the process checks
// before doing anything observable (no Core reads, no egress, no state writes).
package config

import (
	"fmt"
	"strconv"
	"time"
)

// Config holds all telemetry daemon settings resolved from the environment.
type Config struct {
	OptIn  bool
	DryRun bool

	ThreatNetworkURL string
	CoreURL          string
	CoreToken        string

	StateDir     string
	StatusAddr   string
	TickInterval time.Duration

	// Export gate thresholds.
	CandidateMinScore float64
	BehaviorMinScore  float64

	// Read / batch caps.
	ReadCapPerTick int // max events read from Core per tick
	MaxBatchItems  int // max signals per batch (server may override on register)
	MaxBatchesTick int // max batches produced per tick

	VedettaVersion string
}

const (
	defaultThreatNetworkURL = "http://threat-network:9090"
	defaultCoreURL          = "http://backend:8080"
	defaultStateDir         = "/var/lib/vedetta-telemetry"
	defaultStatusAddr       = "127.0.0.1:9091"
	defaultTickInterval     = 15 * time.Minute
	defaultCandidateScore   = 0.85
	defaultBehaviorScore    = 0.70
	defaultReadCap          = 5000
	defaultMaxBatchItems    = 250
	defaultMaxBatchesTick   = 4
	defaultVedettaVersion   = "0.1.0-dev"
)

// Load resolves configuration from the process environment. It returns an error
// only when the daemon is opted in but misconfigured (e.g. missing Core token).
// When opt-in is off, Load never errors: the caller stays inert regardless.
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		OptIn:             getenv("VEDETTA_TELEMETRY_OPTIN") == "true",
		DryRun:            getenv("VEDETTA_TELEMETRY_DRYRUN") == "true",
		ThreatNetworkURL:  orDefault(getenv("VEDETTA_THREAT_NETWORK_URL"), defaultThreatNetworkURL),
		CoreURL:           orDefault(getenv("VEDETTA_CORE_URL"), defaultCoreURL),
		CoreToken:         getenv("VEDETTA_CORE_TOKEN"),
		StateDir:          orDefault(getenv("VEDETTA_TELEMETRY_STATE_DIR"), defaultStateDir),
		StatusAddr:        orDefault(getenv("VEDETTA_TELEMETRY_STATUS_ADDR"), defaultStatusAddr),
		TickInterval:      defaultTickInterval,
		CandidateMinScore: defaultCandidateScore,
		BehaviorMinScore:  defaultBehaviorScore,
		ReadCapPerTick:    defaultReadCap,
		MaxBatchItems:     defaultMaxBatchItems,
		MaxBatchesTick:    defaultMaxBatchesTick,
		VedettaVersion:    orDefault(getenv("VEDETTA_VERSION"), defaultVedettaVersion),
	}

	if v := getenv("VEDETTA_TELEMETRY_TICK_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid VEDETTA_TELEMETRY_TICK_INTERVAL %q: %w", v, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("VEDETTA_TELEMETRY_TICK_INTERVAL must be positive, got %q", v)
		}
		c.TickInterval = d
	}

	var err error
	if c.CandidateMinScore, err = floatEnv(getenv, "VEDETTA_TELEMETRY_CANDIDATE_MIN_SCORE", defaultCandidateScore); err != nil {
		return nil, err
	}
	if c.BehaviorMinScore, err = floatEnv(getenv, "VEDETTA_TELEMETRY_BEHAVIOR_MIN_SCORE", defaultBehaviorScore); err != nil {
		return nil, err
	}
	if c.ReadCapPerTick, err = intEnv(getenv, "VEDETTA_TELEMETRY_READ_CAP", defaultReadCap); err != nil {
		return nil, err
	}
	if c.MaxBatchItems, err = intEnv(getenv, "VEDETTA_TELEMETRY_MAX_BATCH_ITEMS", defaultMaxBatchItems); err != nil {
		return nil, err
	}
	if c.MaxBatchesTick, err = intEnv(getenv, "VEDETTA_TELEMETRY_MAX_BATCHES_PER_TICK", defaultMaxBatchesTick); err != nil {
		return nil, err
	}

	// Validation only matters when the daemon will actually run.
	if c.OptIn {
		if c.CoreToken == "" {
			return nil, fmt.Errorf("VEDETTA_CORE_TOKEN is required when VEDETTA_TELEMETRY_OPTIN=true")
		}
		if c.CandidateMinScore < 0 || c.CandidateMinScore > 1 {
			return nil, fmt.Errorf("VEDETTA_TELEMETRY_CANDIDATE_MIN_SCORE out of range [0,1]: %v", c.CandidateMinScore)
		}
		if c.BehaviorMinScore < 0 || c.BehaviorMinScore > 1 {
			return nil, fmt.Errorf("VEDETTA_TELEMETRY_BEHAVIOR_MIN_SCORE out of range [0,1]: %v", c.BehaviorMinScore)
		}
	}

	return c, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func floatEnv(getenv func(string) string, key string, def float64) (float64, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", key, v, err)
	}
	return f, nil
}

func intEnv(getenv func(string) string, key string, def int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", key, v, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %q", key, v)
	}
	return n, nil
}
