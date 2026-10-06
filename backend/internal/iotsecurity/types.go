// Package iotsecurity validates bounded sensor observations and evaluates
// evidence for Realtek UDPServer exposure and Cling activity. It performs no
// network access and never executes or reads an observed file.
package iotsecurity

import "time"

const (
	MaxBatchObservations = 32
	MaxRequestBytes      = 256 << 10
	MaxPackets           = 16
	MaxPayloadBytes      = 128
	MaxFiles             = 32
	MaxPersistence       = 16
	MaxCoverage          = 64
	CorrelationWindow    = 60 * time.Second

	KindRealtekExploit    = "realtek_exploit"
	KindSTUNFanout        = "stun_fanout"
	KindClingRegistration = "cling_registration"
	KindHostAudit         = "host_audit"
	KindCoverage          = "coverage"

	DetectorRealtekExposure = "realtek_sdk_exposure"
	DetectorRealtekExploit  = "realtek_exploit_attempt"
	DetectorSTUNFanout      = "stun_zero_id_fanout"
	DetectorRegistration    = "cling_registration"
	DetectorArtifact        = "cling_malware_artifact"
	DetectorPersistence     = "cling_persistence"
)

type Observation struct {
	ObservationID string                `json:"observation_id"`
	Timestamp     time.Time             `json:"timestamp"`
	SubjectIP     string                `json:"subject_ip"`
	Kind          string                `json:"kind"`
	Packets       []PacketEvidence      `json:"packets,omitempty"`
	Files         []FileEvidence        `json:"files,omitempty"`
	Persistence   []PersistenceEvidence `json:"persistence,omitempty"`
	SDK           *SDKEvidence          `json:"sdk,omitempty"`
	Coverage      []Coverage            `json:"coverage,omitempty"`
}

type PacketEvidence struct {
	Timestamp       time.Time `json:"timestamp"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	SourcePort      uint16    `json:"source_port"`
	DestinationPort uint16    `json:"destination_port"`
	PayloadHex      string    `json:"payload_hex"`
	PayloadLength   int       `json:"payload_length"`
}

type FileEvidence struct {
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256,omitempty"`
	SHA1       string   `json:"sha1,omitempty"`
	Size       int64    `json:"size"`
	MagicHex   string   `json:"magic_hex,omitempty"`
	Executable bool     `json:"executable"`
	Markers    []string `json:"markers,omitempty"`
}

type PersistenceEvidence struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

type SDKEvidence struct {
	ComponentPath string `json:"component_path"`
	MarkerPath    string `json:"marker_path"`
	Family        string `json:"family"`
	Version       string `json:"version,omitempty"`
}

type Coverage struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Detection contains Core's interpretation of observed facts. A known digest
// proves an artifact match, not its execution; no detection asserts a clean host.
type Detection struct {
	Detector        string
	Category        string
	ObservableType  string
	ObservableValue string
	Confidence      float64
	Score           float64
	Rationale       string
	Details         map[string]any
}
