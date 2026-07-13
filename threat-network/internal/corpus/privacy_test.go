package corpus

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testProfileID  = "11111111-1111-4111-8111-111111111111"
	testProfileID2 = "22222222-2222-4222-8222-222222222222"
	testVariantID  = "33333333-3333-4333-8333-333333333333"
	testVariantID2 = "44444444-4444-4444-8444-444444444444"
	testSourceID   = "55555555-5555-4555-8555-555555555555"
	testSourceID2  = "66666666-6666-4666-8666-666666666666"
	testFactID     = "77777777-7777-4777-8777-777777777777"
	testFactID2    = "88888888-8888-4888-8888-888888888888"
	testMissingID  = "99999999-9999-4999-8999-999999999999"
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

func TestValidatePublicSnapshotAcceptsExplicitVersionAndDateContexts(t *testing.T) {
	t.Parallel()

	snapshot := validPublicSnapshot(t)
	snapshot.Profiles[0].Labels.Model = "Model 2026-07-13"
	snapshot.Profiles[0].Variants[0].VersionFacts[0].Value = "10.1.2"
	snapshot.Profiles[0].Variants[0].Shape.SSDPServerTokens = []string{"ExampleOS/10.1.2 UPnP/1.1"}
	shape, _, hash, _, err := CanonicalizeShape(snapshot.Profiles[0].Variants[0].Shape)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Profiles[0].Variants[0].Shape = shape
	snapshot.Profiles[0].Variants[0].ShapeHash = hash
	if err := ValidatePublicSnapshot(snapshot); err != nil {
		t.Fatalf("explicit product/version context rejected by final gate: %v", err)
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
			name: "bare MAC with adjacent hex in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.SSDPServerTokens = []string{"camera 00005e0053013"}
			},
			marker: "00005e0053013",
		},
		{
			name: "colon MAC with adjacent hex in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.DHCPVendorClasses = []string{"f00:00:5e:00:53:01"}
			},
			marker: "f00:00:5e:00:53:01",
		},
		{
			name: "colon MAC with trailing hex in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.DHCPVendorClasses = []string{"00:00:5e:00:53:01a"}
			},
			marker: "00:00:5e:00:53:01a",
		},
		{
			name: "dash MAC with adjacent hex in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSVendors = []string{"00-00-5e-00-53-01a"}
			},
			marker: "00-00-5e-00-53-01a",
		},
		{
			name: "Cisco MAC with adjacent hex in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"0000.5e00.5301a"}
			},
			marker: "0000.5e00.5301a",
		},
		{
			name: "three word dash MAC in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"0000-5e00-5301"}
			},
			marker: "0000-5e00-5301",
		},
		{
			name: "dotted octet MAC in citation title",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].Title = "camera 00.00.5e.00.53.01"
			},
			marker: "00.00.5e.00.53.01",
		},
		{
			name: "space separated MAC in version fact",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "00 00 5e 00 53 01"
			},
			marker: "00 00 5e 00 53 01",
		},
		{
			name: "dotted IPv4 with adjacent digit in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"9192.168.1.1"}
			},
			marker: "9192.168.1.1",
		},
		{
			name: "dotted IPv4 with trailing digit in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"192.168.1.1255"}
			},
			marker: "192.168.1.1255",
		},
		{
			name: "dotted IPv4 hidden by invalid greedy match",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"192.168.1.9991"}
			},
			marker: "192.168.1.9991",
		},
		{
			name: "dotted IPv4 hidden in oversized octet",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"192.999168.1.1"}
			},
			marker: "192.999168.1.1",
		},
		{
			name: "decimal integer IPv4 in label",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Labels.Model = "router-3232235777"
			},
			marker: "3232235777",
		},
		{
			name: "compact date that is also decimal IPv4",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Labels.Model = "router-20260713"
			},
			marker: "20260713",
		},
		{
			name: "hex IPv4 in citation title",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].Title = "router 0xc0a80101"
			},
			marker: "0xc0a80101",
		},
		{
			name: "octal IPv4 in version fact",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "030052000401"
			},
			marker: "030052000401",
		},
		{
			name: "short private IPv4 in shape",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"router-192.168.1"}
			},
			marker: "192.168.1",
		},
		{
			name: "IPv6 with adjacent hexadecimal prefix",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.MDNSModels = []string{"camera f2001:db8::1"}
			},
			marker: "f2001:db8::1",
		},
		{
			name: "UUID v7 in version fact",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "build 01890f4e-7cc2-7a5d-923f-33f15cfa16c9"
			},
			marker: "01890f4e-7cc2-7a5d-923f-33f15cfa16c9",
		},
		{
			name: "UUID with adjacent hex in version fact",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "build 01890f4e-7cc2-7a5d-923f-33f15cfa16c9f"
			},
			marker: "01890f4e-7cc2-7a5d-923f-33f15cfa16c9f",
		},
		{
			name: "semantic version prerelease containing IPv4",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "v1.2-192.168.1.1"
			},
			marker: "192.168.1.1",
		},
		{
			name: "semantic version build containing IPv4",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VersionFacts[0].Value = "v1.2+192.168.1.1"
			},
			marker: "192.168.1.1",
		},
		{
			name: "identifier in hostname template",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.HostnameTemplates = []string{"cam-00005e0053013-{hex}"}
			},
			marker: "00005e0053013",
		},
		{
			name: "identifier in SSDP device URN",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Shape.SSDPDeviceTypes = []string{"urn:example:device:camera00005e0053013:1"}
			},
			marker: "00005e0053013",
		},
		{
			name: "identifier in variant key",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].VariantKey = "release-00005e0053013"
			},
			marker: "00005e0053013",
		},
		{
			name: "identifier in citation license",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].LicenseCode = "CC-00005e0053013"
			},
			marker: "00005e0053013",
		},
		{
			name: "identifier in citation title",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].Title = "camera 00005e0053013"
			},
			marker: "00005e0053013",
		},
		{
			name: "decimal integer IP in citation host",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].PublicURL = "https://3232235777.example.com/camera"
			},
			marker: "3232235777",
		},
		{
			name: "mixed legacy IP in citation path",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].PublicURL = "https://docs.example.com/router/0xc0.0250.1.1"
			},
			marker: "0xc0.0250.1.1",
		},
		{
			name: "bracketed IPv6 in citation host",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].PublicURL = "https://[2001:db8::1]/camera"
			},
			marker: "2001:db8::1",
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

func TestValidatePublicSnapshotAllowsCanonicalServerIDsOnlyInIDFields(t *testing.T) {
	t.Parallel()

	snapshot := validPublicSnapshot(t)
	// UUIDs are safe here because these values are generated by the corpus
	// service and never derived from a household observation.
	if err := ValidatePublicSnapshot(snapshot); err != nil {
		t.Fatalf("server-generated opaque IDs rejected: %v", err)
	}

	snapshot.Profiles[0].Variants[0].VersionFacts[0].Value = snapshot.Profiles[0].ProfileID
	if err := ValidatePublicSnapshot(snapshot); err == nil {
		t.Fatal("same UUID unexpectedly accepted in a corpus value")
	}
}

func TestValidatePublicSnapshotRejectsDescriptiveOrNonCanonicalIDsWithoutEcho(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		marker string
		mutate func(*PublicSnapshot)
	}{
		{
			name: "descriptive profile ID", marker: "alice-office-router",
			mutate: func(s *PublicSnapshot) { s.Profiles[0].ProfileID = "alice-office-router" },
		},
		{
			name: "descriptive variant ID", marker: "living-room-camera",
			mutate: func(s *PublicSnapshot) { s.Profiles[0].Variants[0].VariantID = "living-room-camera" },
		},
		{
			name: "descriptive predecessor ID", marker: "old-bedroom-camera",
			mutate: func(s *PublicSnapshot) { s.Profiles[0].Variants[0].PredecessorVariantID = "old-bedroom-camera" },
		},
		{
			name: "descriptive source ID", marker: "owner-manual-scan",
			mutate: func(s *PublicSnapshot) {
				s.Profiles[0].Variants[0].Sources[0].SourceID = "owner-manual-scan"
				s.Profiles[0].Variants[0].VersionFacts[0].SourceID = "owner-manual-scan"
			},
		},
		{
			name: "descriptive fact ID", marker: "router-firmware-fact",
			mutate: func(s *PublicSnapshot) { s.Profiles[0].Variants[0].VersionFacts[0].FactID = "router-firmware-fact" },
		},
		{
			name: "UUIDv7", marker: "01890f4e-7cc2-7a5d-923f-33f15cfa16c9",
			mutate: func(s *PublicSnapshot) { s.Profiles[0].ProfileID = "01890f4e-7cc2-7a5d-923f-33f15cfa16c9" },
		},
		{
			name: "uppercase UUIDv4", marker: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
			mutate: func(s *PublicSnapshot) { s.Profiles[0].ProfileID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
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
				t.Fatal("non-canonical public ID unexpectedly accepted")
			}
			if strings.Contains(err.Error(), tt.marker) {
				t.Fatalf("ID validation error reflected rejected value: %v", err)
			}
		})
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
				s.Profiles[0].Variants[0].VersionFacts[0].SourceID = testMissingID
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
				source.SourceID = testSourceID2
				s.Profiles[0].Variants[0].Sources = append(s.Profiles[0].Variants[0].Sources, source)
			},
		},
		{
			name: "repeated fact content",
			mutate: func(s *PublicSnapshot) {
				fact := s.Profiles[0].Variants[0].VersionFacts[0]
				fact.FactID = testFactID2
				s.Profiles[0].Variants[0].VersionFacts = append(s.Profiles[0].Variants[0].VersionFacts, fact)
			},
		},
		{
			name: "repeated fact with conflicting confidence",
			mutate: func(s *PublicSnapshot) {
				fact := s.Profiles[0].Variants[0].VersionFacts[0]
				fact.FactID = testFactID2
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
	missing.Profiles[0].Variants[0].PredecessorVariantID = testMissingID
	if err := ValidatePublicSnapshot(missing); err == nil {
		t.Fatal("predecessor outside the snapshot unexpectedly accepted")
	}

	valid := validPublicSnapshot(t)
	child := valid.Profiles[0].Variants[0]
	child.VariantID = testVariantID2
	child.VariantKey = "firmware-3"
	child.PredecessorVariantID = testVariantID
	child.Sources[0].SourceID = testSourceID2
	child.VersionFacts[0].FactID = testFactID2
	child.VersionFacts[0].SourceID = testSourceID2
	valid.Profiles[0].Variants = append(valid.Profiles[0].Variants, child)
	if err := ValidatePublicSnapshot(valid); err != nil {
		t.Fatalf("closed acyclic lineage rejected: %v", err)
	}

	cycle := valid
	cycle.Profiles[0].Variants[0].PredecessorVariantID = testVariantID2
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
				ProfileID: testProfileID,
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
						VariantID:    testVariantID,
						VariantKey:   "firmware-2",
						Revision:     3,
						ShapeHash:    hash,
						Shape:        shape,
						ConfidenceBP: 9_500,
						VersionFacts: []VersionFact{
							{
								FactID:       testFactID,
								Attribute:    "firmware_version",
								Relation:     "exact",
								Value:        "2.4.1",
								ConfidenceBP: 9_500,
								SourceID:     testSourceID,
							},
						},
						Sources: []Source{
							{
								SourceID:    testSourceID,
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
