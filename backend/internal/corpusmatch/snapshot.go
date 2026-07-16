// Package corpusmatch performs local, read-only device recognition against a signed
// community device-fingerprint corpus snapshot (spec 008 / #52). It never contributes,
// transmits, or stores anything network-facing: it loads a pulled, signature-verified
// snapshot and matches a device's already-observed signals against curated device-class
// shapes, emitting a class-level (vendor / device_type / model) hint.
//
// The backend and threat-network are separate Go modules, so the public snapshot wire types
// are replicated here from the corpus public contract (threat-network/internal/corpus).
// Parsing is lenient — unknown fields (curator/version-fact/source metadata the matcher does
// not need) are ignored — because the snapshot is trusted only after the Phase-3 signature
// check.
package corpusmatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// snapshotSchemaVersion is the corpus schema this matcher understands.
const snapshotSchemaVersion = 1

// Bounds guard against a malformed or oversized snapshot exhausting a Pi-4.
const (
	// MaxSnapshotBytes is the on-disk limit shared by the runtime loader and release checker.
	MaxSnapshotBytes = 32 << 20 // 32 MiB on disk
	maxSnapshotBytes = MaxSnapshotBytes
	maxProfiles      = 20000
	maxVariants      = 60000
)

// CanonicalShapeV1 mirrors threat-network corpus.CanonicalShapeV1 (the public device-class
// shape). Only the matchable signal fields are modeled.
type CanonicalShapeV1 struct {
	SchemaVersion     int      `json:"schema_version"`
	DHCPOption55      []uint16 `json:"dhcp_option_55,omitempty"`
	DHCPVendorClasses []string `json:"dhcp_vendor_classes,omitempty"`
	OUIPrefixes       []string `json:"oui_prefixes,omitempty"`
	HostnameTemplates []string `json:"hostname_templates,omitempty"`
	MDNSServices      []string `json:"mdns_services,omitempty"`
	MDNSModels        []string `json:"mdns_models,omitempty"`
	MDNSVendors       []string `json:"mdns_vendors,omitempty"`
	SSDPDeviceTypes   []string `json:"ssdp_device_types,omitempty"`
	SSDPServerTokens  []string `json:"ssdp_server_tokens,omitempty"`
	TCPPorts          []uint16 `json:"tcp_ports,omitempty"`
	UDPPorts          []uint16 `json:"udp_ports,omitempty"`
}

// Labels is the public class labeling for a profile.
type Labels struct {
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	ProductFamily string `json:"product_family,omitempty"`
	DeviceType    string `json:"device_type"`
	OSFamily      string `json:"os_family,omitempty"`
}

// Variant is one shape under a profile. confidence_bp is basis points (0..10000).
type Variant struct {
	VariantID    string           `json:"variant_id"`
	VariantKey   string           `json:"variant_key"`
	ShapeHash    string           `json:"shape_hash"`
	Shape        CanonicalShapeV1 `json:"shape"`
	ConfidenceBP int              `json:"confidence_bp"`
}

// Profile groups variants that share class labels.
type Profile struct {
	ProfileID string    `json:"profile_id"`
	Revision  int       `json:"revision"`
	Labels    Labels    `json:"labels"`
	Variants  []Variant `json:"variants"`
}

// Snapshot is the public corpus snapshot delivered via the signed device-DB bundle.
type Snapshot struct {
	SchemaVersion  int       `json:"schema_version"`
	CorpusRevision int64     `json:"corpus_revision"`
	GeneratedAt    string    `json:"generated_at"`
	Profiles       []Profile `json:"profiles"`
}

// ParseSnapshot decodes and structurally validates a corpus snapshot. It tolerates unknown
// fields (the public snapshot carries version-fact/source metadata the matcher ignores) but
// rejects an unrecognized schema version or an over-large snapshot.
func ParseSnapshot(data []byte) (*Snapshot, error) {
	if len(data) > maxSnapshotBytes {
		return nil, fmt.Errorf("corpusmatch: snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("corpusmatch: decode snapshot: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("corpusmatch: snapshot contains trailing JSON")
		}
		return nil, fmt.Errorf("corpusmatch: decode trailing snapshot data: %w", err)
	}
	if s.SchemaVersion != snapshotSchemaVersion {
		return nil, fmt.Errorf("corpusmatch: unsupported snapshot schema %d", s.SchemaVersion)
	}
	if s.CorpusRevision < 0 {
		return nil, fmt.Errorf("corpusmatch: corpus_revision cannot be negative")
	}
	if len(s.Profiles) > maxProfiles {
		return nil, fmt.Errorf("corpusmatch: snapshot lists too many profiles (%d)", len(s.Profiles))
	}
	profileIDs := make(map[string]struct{}, len(s.Profiles))
	variantIDs := make(map[string]struct{})
	total := 0
	for pi := range s.Profiles {
		profile := &s.Profiles[pi]
		if profile.ProfileID == "" || strings.TrimSpace(profile.ProfileID) != profile.ProfileID {
			return nil, fmt.Errorf("corpusmatch: profiles[%d].profile_id is required and cannot have surrounding whitespace", pi)
		}
		if _, duplicate := profileIDs[profile.ProfileID]; duplicate {
			return nil, fmt.Errorf("corpusmatch: duplicate profile_id %q", profile.ProfileID)
		}
		profileIDs[profile.ProfileID] = struct{}{}
		total += len(profile.Variants)
		if total > maxVariants {
			return nil, fmt.Errorf("corpusmatch: snapshot lists too many variants (%d)", total)
		}
		for vi := range profile.Variants {
			variant := &profile.Variants[vi]
			path := fmt.Sprintf("profiles[%d].variants[%d]", pi, vi)
			if variant.VariantID == "" || strings.TrimSpace(variant.VariantID) != variant.VariantID {
				return nil, fmt.Errorf("corpusmatch: %s.variant_id is required and cannot have surrounding whitespace", path)
			}
			if _, duplicate := variantIDs[variant.VariantID]; duplicate {
				return nil, fmt.Errorf("corpusmatch: duplicate variant_id %q", variant.VariantID)
			}
			variantIDs[variant.VariantID] = struct{}{}
			if variant.ConfidenceBP < 0 || variant.ConfidenceBP > 10000 {
				return nil, fmt.Errorf("corpusmatch: %s.confidence_bp must be 0..10000", path)
			}
			if variant.Shape.SchemaVersion != snapshotSchemaVersion {
				return nil, fmt.Errorf("corpusmatch: %s.shape has unsupported schema_version %d", path, variant.Shape.SchemaVersion)
			}
		}
	}
	return &s, nil
}
