package export

// Signal is a single wire record (contract §4). It is what the transmitter
// serializes into the batch envelope. It carries aggregate COUNTS only — no
// source_hash, no per-asset identifier, ever.
type Signal struct {
	SignalID   string `json:"signal_id"`
	Kind       Kind   `json:"kind"`
	TimeBucket string `json:"time_bucket"`

	// Domain only present on known_bad_domain_hit.
	Domain string `json:"domain,omitempty"`
	// ETLDPlusOne present on domain-bearing kinds.
	ETLDPlusOne string `json:"etld_plus_one,omitempty"`
	// Behavior only present on behavior_summary.
	Behavior Behavior `json:"behavior,omitempty"`

	LocalConfidence float64  `json:"local_confidence"`
	LocalReasons    []string `json:"local_reasons"`

	ObservationCount   int `json:"observation_count"`
	DistinctAssetCount int `json:"distinct_asset_count"`

	// BlockedCount is a pointer so it can be omitted for kinds where it does not
	// apply (only known_bad_domain_hit carries it per contract §4.1).
	BlockedCount *int `json:"blocked_count,omitempty"`
}

// Batch is the top-level envelope (contract §3). No other top-level keys are
// permitted — the receiver rejects unknown keys in strict mode.
type Batch struct {
	SchemaVersion int      `json:"schema_version"`
	BatchID       string   `json:"batch_id"`
	GeneratedAt   string   `json:"generated_at"`
	WindowStart   string   `json:"window_start"`
	WindowEnd     string   `json:"window_end"`
	Signals       []Signal `json:"signals"`
}

// SchemaVersion is the pinned wire schema version this producer emits.
const SchemaVersion = 1

// Contract caps (contract §4).
const (
	MaxObservationCount   = 10000
	MaxDistinctAssetCount = 500
)
