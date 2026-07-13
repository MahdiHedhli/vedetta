package corpus

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidatePublicSnapshotAcceptsPrivacyReducedCorpus(t *testing.T) {
	t.Parallel()

	snapshot := validPublicSnapshot(t)
	if err := ValidatePublicSnapshot(snapshot); err != nil {
		t.Fatalf("ValidatePublicSnapshot() error = %v", err)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, requestOnly := range []string{"source_ref", "reason_code", "actor", "request_id", "status"} {
		if strings.Contains(string(encoded), `"`+requestOnly+`"`) {
			t.Fatalf("public snapshot leaked non-public field %q: %s", requestOnly, encoded)
		}
	}
	if !strings.Contains(string(encoded), `"dhcp_option_55":[1,3,6,15,119]`) {
		t.Fatalf("DHCP option ordering is not a numeric JSON sequence: %s", encoded)
	}
}

func TestValidatePublicSnapshotAcceptsEmptyBootstrapOnlyAtRevisionZero(t *testing.T) {
	t.Parallel()

	bootstrap := PublicSnapshot{
		SchemaVersion:  SchemaVersion,
		CorpusRevision: 0,
		GeneratedAt:    time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC),
		Profiles:       []PublicProfile{},
	}
	if err := ValidatePublicSnapshot(bootstrap); err != nil {
		t.Fatalf("empty bootstrap snapshot rejected: %v", err)
	}
	bootstrap.Profiles = validPublicSnapshot(t).Profiles
	if err := ValidatePublicSnapshot(bootstrap); err == nil {
		t.Fatal("revision-zero snapshot with published content unexpectedly accepted")
	}
	bootstrap.Profiles = nil
	bootstrap.CorpusRevision = -1
	if err := ValidatePublicSnapshot(bootstrap); err == nil {
		t.Fatal("negative corpus revision unexpectedly accepted")
	}
}

func TestValidatePublicSnapshotRejectsForbiddenValuesAcrossPublication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*PublicSnapshot)
		marker string
	}{
		{
			name: "IP in label",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Labels.Model = "Camera 192.0.2.20"
			},
			marker: "192.0.2.20",
		},
		{
			name: "CIDR in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"camera 198.51.100.0/24"}
			},
			marker: "198.51.100.0/24",
		},
		{
			name: "IPv4 hidden in DNS labels",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"192.0.2.20.example.com"}
			},
			marker: "192.0.2.20.example.com",
		},
		{
			name: "IPv4 with leading zeroes",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"camera 192.000.002.020"}
			},
			marker: "192.000.002.020",
		},
		{
			name: "MAC in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.SSDPServerTokens = []string{"camera 00:00:5e:00:53:01"}
			},
			marker: "00:00:5e:00:53:01",
		},
		{
			name: "Cisco MAC in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.SSDPServerTokens = []string{"camera 0000.5e00.5301"}
			},
			marker: "0000.5e00.5301",
		},
		{
			name: "bare MAC in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.SSDPServerTokens = []string{"camera 00005e005301"}
			},
			marker: "00005e005301",
		},
		{
			name: "UUID v7 in version fact",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "build 01890f4e-7cc2-7a5d-923f-33f15cfa16c9"
			},
			marker: "01890f4e-7cc2-7a5d-923f-33f15cfa16c9",
		},
		{
			name: "private hostname in citation title",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].Title = "Captured from living-room.local"
			},
			marker: "living-room.local",
		},
		{
			name: "private citation URL",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].PublicURL = "https://router.lan/device"
			},
			marker: "router.lan",
		},
		{
			name: "URL outside citation field",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].Title = "docs.example.com/private-device"
			},
			marker: "docs.example.com/private-device",
		},
		{
			name: "dynamic serial identifier",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "serial=SN123456789"
			},
			marker: "SN123456789",
		},
		{
			name: "request source reference leaked",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].SourceRef = "vendor-citation"
			},
			marker: "vendor-citation",
		},
		{
			name: "request fact reference leaked",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].SourceRef = "vendor-citation"
			},
			marker: "vendor-citation",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snapshot := validPublicSnapshot(t)
			tt.mutate(&snapshot)
			err := ValidatePublicSnapshot(snapshot)
			if err == nil {
				t.Fatal("ValidatePublicSnapshot() unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), tt.marker) {
				t.Fatalf("privacy error echoed forbidden value: %v", err)
			}
			var privacyErr *CorpusPrivacyError
			if !errors.As(err, &privacyErr) {
				t.Fatalf("error %T is not a CorpusPrivacyError: %v", err, err)
			}
			if privacyErr.Path == "" || privacyErr.Rule == "" {
				t.Fatalf("privacy error lacks safe diagnostics: %#v", privacyErr)
			}
		})
	}
}

func TestValidatePublicSnapshotAllowsOpaqueServerIDsOnlyInIDFields(t *testing.T) {
	t.Parallel()

	snapshot := validPublicSnapshot(t)
	// UUIDs are safe here because these values are generated by the corpus
	// service and never derived from a household observation.
	snapshot.Profiles[0].ProfileID = "550e8400-e29b-41d4-a716-446655440000"
	snapshot.Profiles[0].Variants[0].VariantID = "01890f4e-7cc2-7a5d-923f-33f15cfa16c9"
	snapshot.Profiles[0].Variants[0].Sources[0].SourceID = "164851c7-522f-4c45-a7d4-8f08c9c962a2"
	snapshot.Profiles[0].Variants[0].VersionFacts[0].FactID = "095a100a-236f-471c-aea3-f326d0e974e2"
	snapshot.Profiles[0].Variants[0].VersionFacts[0].SourceID = snapshot.Profiles[0].Variants[0].Sources[0].SourceID
	if err := ValidatePublicSnapshot(snapshot); err != nil {
		t.Fatalf("server-generated opaque IDs rejected: %v", err)
	}

	snapshot.Profiles[0].Variants[0].VersionFacts[0].Value = snapshot.Profiles[0].ProfileID
	if err := ValidatePublicSnapshot(snapshot); err == nil {
		t.Fatal("same UUID unexpectedly accepted in a corpus value")
	}
}

func TestValidatePublicSnapshotRejectsNonCanonicalOrUnboundContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*PublicSnapshot)
	}{
		{
			name: "shape hash mismatch",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].ShapeHash = strings.Repeat("0", 64)
			},
		},
		{
			name: "noncanonical set order",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.TCPPorts = []uint16{554, 80}
			},
		},
		{
			name: "unknown fact source",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].SourceID = "source_missing"
			},
		},
		{
			name: "duplicate profile ID",
			mutate: func(s *PublicSnapshot) {
				s.Profiles = append(s.Profiles, s.Profiles[0])
			},
		},
		{
			name: "duplicate source ID",
			mutate: func(s *PublicSnapshot) {
				source := s.Profiles[0].Variants[0].Sources[0]
				s.Profiles[0].Variants[0].Sources = append(s.Profiles[0].Variants[0].Sources, source)
			},
		},
		{
			name: "duplicate citation content",
			mutate: func(s *PublicSnapshot) {
				source := s.Profiles[0].Variants[0].Sources[0]
				source.SourceID = "source_002"
				s.Profiles[0].Variants[0].Sources = append(s.Profiles[0].Variants[0].Sources, source)
			},
		},
		{
			name: "repeated fact content",
			mutate: func(s *PublicSnapshot) {
				fact := s.Profiles[0].Variants[0].VersionFacts[0]
				fact.FactID = "fact_002"
				s.Profiles[0].Variants[0].VersionFacts = append(s.Profiles[0].Variants[0].VersionFacts, fact)
			},
		},
		{
			name: "repeated fact with conflicting confidence",
			mutate: func(s *PublicSnapshot) {
				fact := s.Profiles[0].Variants[0].VersionFacts[0]
				fact.FactID = "fact_002"
				fact.ConfidenceBP = 8_000
				s.Profiles[0].Variants[0].VersionFacts = append(s.Profiles[0].Variants[0].VersionFacts, fact)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snapshot := validPublicSnapshot(t)
			tt.mutate(&snapshot)
			if err := ValidatePublicSnapshot(snapshot); err == nil {
				t.Fatal("ValidatePublicSnapshot() unexpectedly succeeded")
			}
		})
	}
}

func TestValidatePublicSnapshotRequiresClosedAcyclicVariantLineage(t *testing.T) {
	t.Parallel()

	missing := validPublicSnapshot(t)
	missing.Profiles[0].Variants[0].PredecessorVariantID = "variant_missing"
	if err := ValidatePublicSnapshot(missing); err == nil {
		t.Fatal("predecessor outside the snapshot unexpectedly accepted")
	}

	valid := validPublicSnapshot(t)
	child := valid.Profiles[0].Variants[0]
	child.VariantID = "variant_002"
	child.VariantKey = "firmware-3"
	child.PredecessorVariantID = "variant_001"
	child.Sources[0].SourceID = "source_002"
	child.VersionFacts[0].FactID = "fact_002"
	child.VersionFacts[0].SourceID = "source_002"
	valid.Profiles[0].Variants = append(valid.Profiles[0].Variants, child)
	if err := ValidatePublicSnapshot(valid); err != nil {
		t.Fatalf("closed acyclic lineage rejected: %v", err)
	}

	cycle := valid
	cycle.Profiles[0].Variants[0].PredecessorVariantID = "variant_002"
	if err := ValidatePublicSnapshot(cycle); err == nil {
		t.Fatal("cyclic predecessor graph unexpectedly accepted")
	}
}

func TestPublicTypeAllowlistHasNoDynamicExtensionPoint(t *testing.T) {
	t.Parallel()

	if err := validatePublicTypeAllowlist(); err != nil {
		t.Fatalf("public corpus schema violates structural privacy allowlist: %v", err)
	}
}

func validPublicSnapshot(t *testing.T) PublicSnapshot {
	t.Helper()

	shape, _, hash, _, err := CanonicalizeShape(CanonicalShapeV1{
		DHCPOption55:      []uint16{1, 3, 6, 15, 119},
		DHCPVendorClasses: []string{"android-dhcp-14"},
		OUIPrefixes:       []string{"00:00:5e"},
		HostnameTemplates: []string{"camera-{hex}"},
		MDNSServices:      []string{"_rtsp._tcp.local."},
		MDNSModels:        []string{"Example Camera Two"},
		MDNSVendors:       []string{"Example Devices"},
		SSDPDeviceTypes:   []string{"urn:schemas-upnp-org:device:DigitalSecurityCamera:1"},
		SSDPServerTokens:  []string{"ExampleOS/2 UPnP/1.1 ExampleCamera/2"},
		TCPPorts:          []uint16{80, 443, 554},
		UDPPorts:          []uint16{1900, 5353},
	})
	if err != nil {
		t.Fatalf("building valid canonical shape: %v", err)
	}
	return PublicSnapshot{
		SchemaVersion:  SchemaVersion,
		CorpusRevision: 7,
		GeneratedAt:    time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC),
		Profiles: []PublicProfile{
			{
				ProfileID: "profile_001",
				Revision:  2,
				Labels: ProfileLabels{
					Manufacturer:  "Example Devices",
					Model:         "Camera Two",
					ProductFamily: "Vision",
					DeviceType:    "camera",
					OSFamily:      "embedded",
				},
				Variants: []PublicVariant{
					{
						VariantID:    "variant_001",
						VariantKey:   "firmware-2",
						Revision:     3,
						ShapeHash:    hash,
						Shape:        shape,
						ConfidenceBP: 9_500,
						VersionFacts: []VersionFact{
							{
								FactID:       "fact_001",
								Attribute:    "firmware_version",
								Relation:     "exact",
								Value:        "2.4.1",
								ConfidenceBP: 9_500,
								SourceID:     "source_001",
							},
						},
						Sources: []Source{
							{
								SourceID:    "source_001",
								Kind:        "vendor_doc",
								Title:       "Example Camera Support",
								PublicURL:   "https://docs.example.com/camera-two",
								RetrievedAt: "2026-07-13T16:00:00Z",
								LicenseCode: "CC-BY-4.0",
							},
						},
					},
				},
			},
		},
	}
}
