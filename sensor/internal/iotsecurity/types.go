// Package iotsecurity collects bounded passive network and filesystem evidence.
// It does not execute probes or inspected files, and Core owns all verdicts.
package iotsecurity

import "time"

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

// Config configures native passive collection. CIDR constrains logical subjects,
// not the public peers with which those subjects communicate.
type Config struct {
	Interface     string
	CoreURL       string
	CIDR          string
	Promiscuous   bool
	OnObservation func(Observation)
}
