// Package export is the privacy boundary. It gates which events may leave the
// node, strips them to a structurally-allowlisted ExportCandidate, and
// aggregates candidates into wire Signals that carry counts — never per-asset
// identifiers.
//
// The central guarantee is STRUCTURAL: ExportCandidate has no field capable of
// holding a raw source IP, MAC, hostname, or free-form metadata. Forbidden data
// is dropped by construction, not by a blocklist that could miss a field. The
// one device-linked value, SourceHash, is tagged json:"-" and is discarded by
// the aggregator before any serialization.
package export

// Kind is one of the three signal kinds in the wire contract.
type Kind string

const (
	KindKnownBadDomainHit Kind = "known_bad_domain_hit"
	KindHighConfCandidate Kind = "high_confidence_domain_candidate"
	KindBehaviorSummary   Kind = "behavior_summary"
)

// Behavior enumerates the behavior_summary values in the contract §4.3.
type Behavior string

const (
	BehaviorBeaconing       Behavior = "dns_beaconing_candidate"
	BehaviorDGABurst        Behavior = "dga_burst_candidate"
	BehaviorTunneling       Behavior = "dns_tunneling_candidate"
	BehaviorNewDomainVolume Behavior = "new_domain_volume_anomaly"
)

// ExportCandidate is the ONLY representation an event may take after stripping.
// Its fields are exactly the plan.md allowlist. There is deliberately no field
// for source_ip, resolved_ip, server_ip, event_id, exact timestamp, geo,
// device_vendor, network_segment, dns_source, threat_desc, metadata, hostname,
// MAC, notes, or any free-form string — such data cannot be represented here.
type ExportCandidate struct {
	Kind Kind `json:"kind"`

	// Domain is the exact FQDN and is populated ONLY for known_bad_domain_hit.
	Domain string `json:"domain,omitempty"`
	// ETLDPlusOne is the registrable domain (candidates and known-bad).
	ETLDPlusOne string `json:"etld_plus_one,omitempty"`
	// Behavior is set ONLY for behavior_summary (no domain material).
	Behavior Behavior `json:"behavior,omitempty"`

	// TimeBucket is the event time truncated to the hour, RFC3339 UTC.
	TimeBucket string `json:"time_bucket"`
	// LocalConfidence is clamped to [0,1].
	LocalConfidence float64 `json:"local_confidence"`
	// LocalReasons is the intersection of event tags with the fixed vocabulary.
	LocalReasons []string `json:"local_reasons"`
	// Blocked mirrors the event's blocked flag; folded into blocked_count on aggregate.
	Blocked bool `json:"blocked,omitempty"`

	// SourceHash is INTERNAL ONLY. It exists so the aggregator can count
	// distinct assets. json:"-" guarantees it never serializes; the aggregator
	// discards it entirely before producing a Signal.
	SourceHash string `json:"-"`
}
