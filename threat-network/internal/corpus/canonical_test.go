package corpus

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalShapeGoldenVector(t *testing.T) {
	t.Parallel()

	input := CanonicalShapeV1{
		DHCPOption55:      []uint16{1, 3, 6, 15, 119},
		DHCPVendorClasses: []string{" Vendor OS 2 ", "Alpha   OS", "vendor os 2"},
		OUIPrefixes:       []string{"00:11:22", "00-00-5e"},
		HostnameTemplates: []string{"camera-{HEX}"},
		MDNSServices:      []string{"_rtsp._tcp.local.", "_airplay._tcp"},
		MDNSModels:        []string{" Camera Two "},
		MDNSVendors:       []string{"Example Devices"},
		SSDPDeviceTypes:   []string{"URN:schemas-upnp-org:device:DigitalSecurityCamera:1"},
		SSDPServerTokens:  []string{"ExampleOS/2 UPnP/1.1 ExampleCamera/2"},
		TCPPorts:          []uint16{554, 80, 443, 554},
		UDPPorts:          []uint16{5353, 1900},
	}

	got, canonical, hash, families, err := CanonicalizeShape(input)
	if err != nil {
		t.Fatalf("CanonicalizeShape() error = %v", err)
	}
	wantJSON := `{"schema_version":1,"dhcp_option_55":[1,3,6,15,119],"dhcp_vendor_classes":["alpha os","vendor os 2"],"oui_prefixes":["00005E","001122"],"hostname_templates":["camera-{hex}"],"mdns_services":["_airplay._tcp","_rtsp._tcp"],"mdns_models":["camera two"],"mdns_vendors":["example devices"],"ssdp_device_types":["urn:schemas-upnp-org:device:digitalsecuritycamera:1"],"ssdp_server_tokens":["exampleos/2 upnp/1.1 examplecamera/2"],"tcp_ports":[80,443,554],"udp_ports":[1900,5353]}`
	if string(canonical) != wantJSON {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", canonical, wantJSON)
	}
	const wantHash = "a47d6231dfaff6eedff29a118f20bcf1f4add66ca3829c2c77eddcb8644d929f"
	if hash != wantHash {
		t.Fatalf("shape content address = %s, want %s", hash, wantHash)
	}
	if families != 6 {
		t.Fatalf("families = %d, want 6", families)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", got.SchemaVersion, SchemaVersion)
	}

	// A repeated call is byte-for-byte stable. The digest is a content address,
	// not an anonymization operation.
	got2, canonical2, hash2, families2, err := CanonicalizeShape(input)
	if err != nil {
		t.Fatalf("second CanonicalizeShape() error = %v", err)
	}
	if !reflect.DeepEqual(got, got2) || string(canonical) != string(canonical2) || hash != hash2 || families != families2 {
		t.Fatal("canonicalization is not deterministic")
	}
}

func TestCanonicalShapeRejectsWildcardOnlyHostnameTemplates(t *testing.T) {
	for _, value := range []string{"{hex}", "{digits}", "{random}", "-{hex}_", " {HEX} ", "{hex}{digits}"} {
		t.Run(value, func(t *testing.T) {
			_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{HostnameTemplates: []string{value}})
			if err == nil || !strings.Contains(err.Error(), "alphanumeric literal") {
				t.Fatalf("wildcard-only hostname template %q error = %v", value, err)
			}
		})
	}
	for _, value := range []string{"camera-{hex}", "{digits}-camera", "x{random}", "{hex}-cam_2"} {
		t.Run("accept "+value, func(t *testing.T) {
			if _, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{HostnameTemplates: []string{value}}); err != nil {
				t.Fatalf("constrained hostname template %q rejected: %v", value, err)
			}
		})
	}
}

func TestCanonicalShapeSetOrderingDoesNotChangeHash(t *testing.T) {
	t.Parallel()

	a := CanonicalShapeV1{
		DHCPOption55:      []uint16{1, 3, 6, 15},
		DHCPVendorClasses: []string{"vendor-b", "vendor-a"},
		OUIPrefixes:       []string{"001122", "00005E"},
		MDNSServices:      []string{"_rtsp._tcp", "_airplay._tcp"},
		TCPPorts:          []uint16{554, 80, 443},
	}
	b := CanonicalShapeV1{
		DHCPOption55:      []uint16{1, 3, 6, 15},
		DHCPVendorClasses: []string{"vendor-a", "vendor-b", "vendor-a"},
		OUIPrefixes:       []string{"00:00:5e", "00:11:22"},
		MDNSServices:      []string{"_airplay._tcp.local.", "_rtsp._tcp"},
		TCPPorts:          []uint16{80, 443, 554, 80},
	}
	canonicalA, bytesA, hashA, _, err := CanonicalizeShape(a)
	if err != nil {
		t.Fatal(err)
	}
	canonicalB, bytesB, hashB, _, err := CanonicalizeShape(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonicalA, canonicalB) || string(bytesA) != string(bytesB) || hashA != hashB {
		t.Fatalf("set ordering changed canonical result: %s != %s", hashA, hashB)
	}
}

func TestCanonicalShapeDHCPOptionOrderChangesHash(t *testing.T) {
	t.Parallel()

	a := CanonicalShapeV1{DHCPOption55: []uint16{1, 3, 6, 15}}
	b := CanonicalShapeV1{DHCPOption55: []uint16{3, 1, 6, 15}}
	_, _, hashA, _, err := CanonicalizeShape(a)
	if err != nil {
		t.Fatal(err)
	}
	_, _, hashB, _, err := CanonicalizeShape(b)
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Fatal("ordered DHCP option-55 sequences unexpectedly share a content address")
	}
}

func TestCanonicalShapeRejectsOutOfRangeDHCPOptions(t *testing.T) {
	t.Parallel()

	for _, code := range []uint16{0, 255, 256, 65_535} {
		code := code
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			t.Parallel()
			_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{DHCPOption55: []uint16{code}})
			if err == nil {
				t.Fatalf("DHCP option %d unexpectedly accepted", code)
			}
		})
	}
}

func TestCanonicalShapeRejectsForbiddenIdentifiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "IPv4", value: "camera 192.0.2.20"},
		{name: "IPv4 host port", value: "camera 192.0.2.20:8080"},
		{name: "IPv4 in DNS labels", value: "camera 192.0.2.20.example.com"},
		{name: "IPv4 with leading zeroes", value: "camera 192.000.002.020"},
		{name: "IPv6", value: "camera 2001:db8::1234"},
		{name: "CIDR", value: "camera 198.51.100.0/24"},
		{name: "MAC", value: "camera 00:00:5e:00:53:01"},
		{name: "Cisco MAC", value: "camera 0000.5e00.5301"},
		{name: "bare MAC", value: "camera 00005e005301"},
		{name: "UUID v4", value: "camera 550e8400-e29b-41d4-a716-446655440000"},
		{name: "UUID v7", value: "camera 01890f4e-7cc2-7a5d-923f-33f15cfa16c9"},
		{name: "private local hostname", value: "camera living-room.local"},
		{name: "private LAN hostname embedded", value: "camera router.lan build"},
		{name: "URL", value: "camera https://inventory.example/device"},
		{name: "unschemed URL", value: "camera docs.example.com/device"},
		{name: "serial label", value: "camera serial=SN123456"},
		{name: "serial number label", value: "camera serial number: SN123456"},
		{name: "serial number whitespace", value: "camera Serial Number SN123456789"},
		{name: "client ID label", value: "camera client_id=abcdef123456"},
		{name: "client ID hyphen label", value: "camera client-id=abcdef123456"},
		{name: "token label", value: "camera token:deadbeef"},
		{name: "USN label", value: "camera usn=uuid-value"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{tt.value}})
			if err == nil {
				t.Fatalf("CanonicalizeShape(%q) unexpectedly succeeded", tt.value)
			}
		})
	}
}

func TestIdentifierBoundaryBypassesRejectedAtWriteTimeWithoutEcho(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		marker string
		run    func() error
	}{
		{
			name: "bare MAC with trailing hex in product signal", marker: "00005e0053013",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSVendors: []string{"vendor-00005e0053013"}})
				return err
			},
		},
		{
			name: "colon MAC with leading hex in product signal", marker: "f00:00:5e:00:53:01",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{SSDPServerTokens: []string{"f00:00:5e:00:53:01"}})
				return err
			},
		},
		{
			name: "colon MAC with trailing hex in product signal", marker: "00:00:5e:00:53:01a",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{SSDPServerTokens: []string{"00:00:5e:00:53:01a"}})
				return err
			},
		},
		{
			name: "dash MAC with trailing hex in product signal", marker: "00-00-5e-00-53-01a",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{DHCPVendorClasses: []string{"00-00-5e-00-53-01a"}})
				return err
			},
		},
		{
			name: "Cisco MAC with trailing hex in product signal", marker: "0000.5e00.5301a",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"0000.5e00.5301a"}})
				return err
			},
		},
		{
			name: "Cisco MAC with leading hex in product signal", marker: "f0000.5e00.5301",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"f0000.5e00.5301"}})
				return err
			},
		},
		{
			name: "three word dash MAC in product signal", marker: "0000-5e00-5301",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"0000-5e00-5301"}})
				return err
			},
		},
		{
			name: "dotted octet MAC in product signal", marker: "00.00.5e.00.53.01",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"00.00.5e.00.53.01"}})
				return err
			},
		},
		{
			name: "space separated MAC in product signal", marker: "00 00 5e 00 53 01",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"00 00 5e 00 53 01"}})
				return err
			},
		},
		{
			name: "UUID with trailing hex in label", marker: "550e8400-e29b-41d4-a716-446655440000f",
			run: func() error {
				_, err := ValidateLabels(ProfileLabels{
					Manufacturer: "Example", Model: "550e8400-e29b-41d4-a716-446655440000f",
					DeviceType: "camera", OSFamily: "embedded",
				})
				return err
			},
		},
		{
			name: "UUID with leading hex in label", marker: "f550e8400-e29b-41d4-a716-446655440000",
			run: func() error {
				_, err := ValidateLabels(ProfileLabels{
					Manufacturer: "Example", Model: "f550e8400-e29b-41d4-a716-446655440000",
					DeviceType: "camera", OSFamily: "embedded",
				})
				return err
			},
		},
		{
			name: "dotted IPv4 with leading digit in product signal", marker: "9192.168.1.1",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"9192.168.1.1"}})
				return err
			},
		},
		{
			name: "dotted IPv4 with trailing digit in product signal", marker: "192.168.1.1255",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"192.168.1.1255"}})
				return err
			},
		},
		{
			name: "dotted IPv4 hidden by greedy octet", marker: "192.168.1.9991",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"192.168.1.9991"}})
				return err
			},
		},
		{
			name: "dotted IPv4 hidden inside oversized octet", marker: "192.999168.1.1",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"192.999168.1.1"}})
				return err
			},
		},
		{
			name: "decimal integer IPv4 in label", marker: "3232235777",
			run: func() error {
				_, err := ValidateLabels(ProfileLabels{Manufacturer: "Example", Model: "router-3232235777", DeviceType: "router", OSFamily: "embedded"})
				return err
			},
		},
		{
			name: "compact date that is also decimal IPv4", marker: "20260713",
			run: func() error {
				_, err := ValidateLabels(ProfileLabels{Manufacturer: "Example", Model: "router-20260713", DeviceType: "router", OSFamily: "embedded"})
				return err
			},
		},
		{
			name: "hex IPv4 in version fact", marker: "0xc0a80101",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{Attribute: "firmware_version", Relation: "exact", Value: "build-0xc0a80101"}}, nil)
				return err
			},
		},
		{
			name: "octal IPv4 in citation title", marker: "030052000401",
			run: func() error {
				_, err := NormalizeSources([]Source{{Kind: "vendor_doc", Title: "router 030052000401", PublicURL: "https://docs.example.com/router"}})
				return err
			},
		},
		{
			name: "private shortened IPv4 in product signal", marker: "192.168.1",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"router-192.168.1"}})
				return err
			},
		},
		{
			name: "identifier in hostname template", marker: "00005e0053013",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{HostnameTemplates: []string{"cam-00005e0053013-{hex}"}})
				return err
			},
		},
		{
			name: "identifier in SSDP device URN", marker: "00005e0053013",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{SSDPDeviceTypes: []string{"urn:example:device:camera00005e0053013:1"}})
				return err
			},
		},
		{
			name: "identifier in variant key", marker: "00005e0053013",
			run: func() error {
				_, err := ValidateVariantKey("release-00005e0053013")
				return err
			},
		},
		{
			name: "identifier in citation license", marker: "00005e0053013",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					Kind: "vendor_doc", PublicURL: "https://docs.example.com/camera",
					LicenseCode: "CC-00005e0053013",
				}})
				return err
			},
		},
		{
			name: "identifier in citation title", marker: "00005e0053013",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					Kind: "vendor_doc", Title: "camera 00005e0053013",
					PublicURL: "https://docs.example.com/camera",
				}})
				return err
			},
		},
		{
			name: "identifier in version fact", marker: "00005e0053013",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					Attribute: "firmware_version", Relation: "exact", Value: "build-00005e0053013",
				}}, nil)
				return err
			},
		},
		{
			name: "semantic version prerelease containing IPv4", marker: "192.168.1.1",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					Attribute: "firmware_version", Relation: "exact", Value: "v1.2-192.168.1.1",
				}}, nil)
				return err
			},
		},
		{
			name: "semantic version build containing IPv4", marker: "192.168.1.1",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					Attribute: "firmware_version", Relation: "exact", Value: "v1.2+192.168.1.1",
				}}, nil)
				return err
			},
		},
		{
			name: "bracketed IPv6", marker: "[2001:db8::1]",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"camera [2001:db8::1]"}})
				return err
			},
		},
		{
			name: "IPv6 with adjacent hexadecimal prefix", marker: "f2001:db8::1",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"camera f2001:db8::1"}})
				return err
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.run()
			if err == nil {
				t.Fatal("identifier boundary bypass unexpectedly accepted")
			}
			if strings.Contains(err.Error(), tt.marker) {
				t.Fatalf("privacy error reflected rejected identifier: %v", err)
			}
		})
	}
}

func TestStructurallyReducedSignalsStillAccepted(t *testing.T) {
	t.Parallel()

	if _, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{
		OUIPrefixes:       []string{"00:00:5e"},
		HostnameTemplates: []string{"camera-{hex}"},
		MDNSServices:      []string{"_rtsp._tcp"},
		SSDPDeviceTypes:   []string{"urn:schemas-upnp-org:device:DigitalSecurityCamera:1"},
	}); err != nil {
		t.Fatalf("fixed, structurally reduced signals rejected: %v", err)
	}
	if _, err := ValidateVariantKey("firmware-2.4"); err != nil {
		t.Fatalf("ordinary variant key rejected: %v", err)
	}
}

func TestVersionAndFormattedDateProductMetadataStillAccepted(t *testing.T) {
	t.Parallel()

	if _, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{
		SSDPServerTokens: []string{"ExampleOS/10.1.2 UPnP/1.1"},
	}); err != nil {
		t.Fatalf("ordinary product/version server token rejected: %v", err)
	}
	if _, err := NormalizeVersionFacts([]VersionFact{{
		Attribute: "firmware_version", Relation: "exact", Value: "10.1.2",
	}}, nil); err != nil {
		t.Fatalf("version fact resembling a private short IPv4 form rejected: %v", err)
	}
	if _, err := ValidateLabels(ProfileLabels{
		Manufacturer: "Example", Model: "Model 2026-07-13", DeviceType: "router", OSFamily: "embedded",
	}); err != nil {
		t.Fatalf("formatted date model identifier rejected: %v", err)
	}
}

func TestCommonSerialIdentifiersRejectedWithoutEcho(t *testing.T) {
	t.Parallel()

	const serial = "SN123456789"
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "shape product token",
			run: func() error {
				_, _, _, _, err := CanonicalizeShape(CanonicalShapeV1{MDNSModels: []string{"Serial Number " + serial}})
				return err
			},
		},
		{
			name: "profile label",
			run: func() error {
				_, err := ValidateLabels(ProfileLabels{
					Manufacturer: "Example", Model: "Serial Number " + serial,
					DeviceType: "camera", OSFamily: "embedded",
				})
				return err
			},
		},
		{
			name: "citation title",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					Kind: "vendor_doc", Title: "Serial Number " + serial,
					PublicURL: "https://docs.example.com/camera",
				}})
				return err
			},
		},
		{
			name: "version fact",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					Attribute: "firmware_version", Relation: "exact",
					Value: "Serial Number " + serial, ConfidenceBP: 9000,
				}}, nil)
				return err
			},
		},
		{
			name: "same-segment citation path",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					Kind: "vendor_doc", PublicURL: "https://docs.example.com/support/serial-" + serial,
				}})
				return err
			},
		},
		{
			name: "serial number abbreviation",
			run: func() error {
				_, err := ValidateLabels(ProfileLabels{
					Manufacturer: "Example", Model: "Serial No. " + serial,
					DeviceType: "camera", OSFamily: "embedded",
				})
				return err
			},
		},
		{
			name: "slash abbreviation",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					Kind: "vendor_doc", Title: "S/N: " + serial,
					PublicURL: "https://docs.example.com/camera",
				}})
				return err
			},
		},
		{
			name: "compact abbreviation",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					Attribute: "firmware_version", Relation: "exact",
					Value: "SN=" + serial, ConfidenceBP: 9000,
				}}, nil)
				return err
			},
		},
		{
			name: "abbreviated citation path",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					Kind: "vendor_doc", PublicURL: "https://docs.example.com/support/sn-" + serial,
				}})
				return err
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.run()
			if err == nil {
				t.Fatal("common serial identifier unexpectedly accepted")
			}
			if strings.Contains(err.Error(), serial) {
				t.Fatalf("privacy error echoed the rejected serial: %v", err)
			}
		})
	}
}

func TestDynamicIdentifierHeuristicAllowsPublicDocumentationLabels(t *testing.T) {
	t.Parallel()

	if _, err := ValidateLabels(ProfileLabels{
		Manufacturer: "Example", Model: "Serial Number Guide",
		DeviceType: "camera", OSFamily: "embedded",
	}); err != nil {
		t.Fatalf("ordinary public label rejected: %v", err)
	}
	if _, err := NormalizeSources([]Source{{
		Kind: "vendor_doc", PublicURL: "https://docs.example.com/support/serial-number-guide-2026",
	}}); err != nil {
		t.Fatalf("ordinary public documentation path rejected: %v", err)
	}
}

func TestCanonicalShapeAllowsFixedPrivacyReducedSignals(t *testing.T) {
	t.Parallel()

	shape := CanonicalShapeV1{
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
	}
	canonical, encoded, hash, families, err := CanonicalizeShape(shape)
	if err != nil {
		t.Fatalf("privacy-reduced shape rejected: %v", err)
	}
	if len(encoded) == 0 || len(hash) != 64 || families != 6 {
		t.Fatalf("unexpected canonical result: bytes=%d hash=%q families=%d", len(encoded), hash, families)
	}
	if len(canonical.OUIPrefixes) != 1 || canonical.OUIPrefixes[0] != "00005E" {
		t.Fatalf("OUI was not reduced to a 24-bit prefix: %#v", canonical.OUIPrefixes)
	}
}

func TestCanonicalShapeCountsIndependentAcquisitionFamilies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		shape CanonicalShapeV1
	}{
		{"all DHCP fields", CanonicalShapeV1{DHCPOption55: []uint16{1, 3, 6}, DHCPVendorClasses: []string{"example-os"}}},
		{"all mDNS fields", CanonicalShapeV1{MDNSServices: []string{"_http._tcp"}, MDNSModels: []string{"camera two"}, MDNSVendors: []string{"example devices"}}},
		{"all SSDP fields", CanonicalShapeV1{SSDPDeviceTypes: []string{"urn:schemas-upnp-org:device:camera:1"}, SSDPServerTokens: []string{"example/1 upnp/1.1"}}},
		{"both port protocols", CanonicalShapeV1{TCPPorts: []uint16{443}, UDPPorts: []uint16{5353}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, families, err := CanonicalizeShape(tt.shape)
			if err != nil {
				t.Fatal(err)
			}
			if families != 1 {
				t.Fatalf("families = %d, want 1", families)
			}
		})
	}
}

func TestNormalizeSourcesEnforcesCitationPrivacyContract(t *testing.T) {
	t.Parallel()

	got, err := NormalizeSources([]Source{{
		SourceID: testSourceID, Kind: "vendor_doc", Title: "Example Camera Support",
		PublicURL: "https://DOCS.Example.com:443/camera%20two", RetrievedAt: "2026-07-13T12:00:00-04:00",
		LicenseCode: "CC-BY-4.0",
	}})
	if err != nil {
		t.Fatalf("valid citation rejected: %v", err)
	}
	if got[0].SourceID != testSourceID {
		t.Fatalf("server ID was not preserved: %#v", got[0])
	}
	if got[0].PublicURL != "https://docs.example.com/camera%20two" {
		t.Fatalf("citation URL is not canonical: %q", got[0].PublicURL)
	}
	if got[0].RetrievedAt != "2026-07-13T16:00:00Z" {
		t.Fatalf("retrieved_at is not UTC: %q", got[0].RetrievedAt)
	}

	for _, kind := range []string{"lab_observation", "manual_curation"} {
		if _, err = NormalizeSources([]Source{{SourceRef: "local", Kind: kind}}); err != nil {
			t.Fatalf("kind-only %s source rejected: %v", kind, err)
		}
		for _, mutate := range []func(*Source){
			func(s *Source) { s.Title = "Local note" },
			func(s *Source) { s.PublicURL = "https://docs.example.com/note" },
			func(s *Source) { s.RetrievedAt = "2026-07-13T16:00:00Z" },
			func(s *Source) { s.LicenseCode = "private" },
		} {
			source := Source{Kind: kind}
			mutate(&source)
			if _, err = NormalizeSources([]Source{source}); err == nil {
				t.Fatalf("%s source with free-form fields unexpectedly accepted: %#v", kind, source)
			}
		}
	}

	for _, kind := range []string{"vendor_doc", "standards", "security_advisory", "import"} {
		if _, err = NormalizeSources([]Source{{Kind: kind}}); err == nil {
			t.Fatalf("URL-less %s citation unexpectedly accepted", kind)
		}
	}
	if _, err = NormalizeSources([]Source{{Kind: "import", PublicURL: "https://corpus.example.com/device"}}); err == nil {
		t.Fatal("import citation without an explicit license unexpectedly accepted")
	}
	if _, err = NormalizeSources([]Source{{Kind: "import", PublicURL: "https://corpus.example.com/device", LicenseCode: "CC-BY-4.0"}}); err != nil {
		t.Fatalf("licensed import citation rejected: %v", err)
	}
}

func TestNormalizeSourcesRejectsIdentifiersInDecodedURLPaths(t *testing.T) {
	t.Parallel()

	badURLs := []string{
		"https://docs.example.com/router/192.168.1.1",
		"https://docs.example.com/router/%31%39%32%2e%31%36%38%2e%31%2e%31",
		"https://docs.example.com/router/%2531%2539%2532%252e%2531%2536%2538%252e%2531%252e%2531",
		"https://192.168.1.1.nip.example.com/router",
		"https://docs.example.com/device/00%3A00%3A5e%3A00%3A53%3A01",
		"https://docs.example.com/device/0000.5e00.5301",
		"https://docs.example.com/device/2001%3Adb8%3A%3A1234",
		"https://docs.example.com/device/550e8400-e29b-41d4-a716-446655440000",
		"https://docs.example.com/device/router%2Elan",
		"https://docs.example.com/serial/SN123456789",
		"https://docs.example.com/support/serial-SN123456789",
		"https://docs.example.com/support/serial-%53%4e%31%32%33%34%35%36%37%38%39",
		"https://docs.example.com/device-id/SN123456789",
		"https://docs.example.com/%EF%BC%91%EF%BC%99%EF%BC%92",
		"https://localhost/device",
		"https://router/device",
		"https://router.lan/device",
		"https://127.0.0.1/device",
		"https://[::1]/device",
		"https://docs.example.com:invalid/device",
		"https://user:secret@docs.example.com/device",
		"https://docs.example.com/device?serial=SN123",
		"https://docs.example.com/device?",
		"https://docs.example.com/device#serial-SN123",
		"https://docs.example.com/device#",
	}
	for _, rawURL := range badURLs {
		rawURL := rawURL
		t.Run(strings.ReplaceAll(rawURL, "/", "_"), func(t *testing.T) {
			t.Parallel()
			_, err := NormalizeSources([]Source{{Kind: "vendor_doc", PublicURL: rawURL}})
			if err == nil {
				t.Fatalf("citation %q unexpectedly accepted", rawURL)
			}
		})
	}
}

func TestNormalizeSourcesRejectsAlternativeIPv4CitationsWithoutEcho(t *testing.T) {
	t.Parallel()

	badURLs := []struct{ raw, marker string }{
		{"https://3232235777.example.com/support", "3232235777"},
		{"https://0x7f000001.example.com/support", "0x7f000001"},
		{"https://030052000401.example.com/support", "030052000401"},
		{"https://0177.0.0.1.example.com/support", "0177.0.0.1"},
		{"https://0x7f.1.example.com/support", "0x7f.1"},
		{"https://docs.example.com/router/3221226219", "3221226219"},
		{"https://docs.example.com/router/0xc0a80101", "0xc0a80101"},
		{"https://docs.example.com/router/0x00000001", "0x00000001"},
		{"https://docs.example.com/router/030052000401", "030052000401"},
		{"https://docs.example.com/router/0xc0.0250.1.1", "0xc0.0250.1.1"},
		{"https://docs.example.com/router/0300.0250.1.1", "0300.0250.1.1"},
		{"https://docs.example.com/router/127.65535", "127.65535"},
		{"https://docs.example.com/router/10.1", "10.1"},
		{"https://docs.example.com/router/192.168.1", "192.168.1"},
		{"https://docs.example.com/router/.10.1.", "10.1"},
		{"https://docs.example.com/router/10.1.html", "10.1"},
		{"https://docs.example.com/router/ip10.1", "10.1"},
		{"https://docs.example.com/router/3232235777.html", "3232235777"},
		{"https://docs.example.com/router/ip0xc0a80101", "0xc0a80101"},
		{"https://docs.example.com/router/ref-0177.0.0.1.txt", "0177.0.0.1"},
		{"https://docs.example.com/router/0x1", "0x1"},
		{"https://docs.example.com/router/0x01", "0x01"},
		{"https://docs.example.com/router/000000001", "000000001"},
		{"https://0x1.example.com/router", "0x1"},
		{"https://000000001.example.com/router", "000000001"},
		{"https://docs.example.com/router/f2001:db8::1", "2001:db8::1"},
		{"https://docs.example.com/router/%30%78%63%30%61%38%30%31%30%31", "0xc0a80101"},
		{"https://docs.example.com/device/00005e0053013", "00005e0053013"},
		{"https://docs.example.com/device/550e8400-e29b-41d4-a716-446655440000f", "550e8400-e29b-41d4-a716-446655440000f"},
		{"https://[2001:db8::1]/router", "2001:db8::1"},
	}
	for _, candidate := range badURLs {
		candidate := candidate
		t.Run(candidate.raw, func(t *testing.T) {
			t.Parallel()
			_, err := NormalizeSources([]Source{{Kind: "vendor_doc", PublicURL: candidate.raw}})
			if err == nil {
				t.Fatal("alternate IP citation unexpectedly accepted")
			}
			if strings.Contains(err.Error(), candidate.raw) || strings.Contains(err.Error(), candidate.marker) {
				t.Fatalf("privacy error reflected rejected citation: %v", err)
			}
		})
	}
}

func TestNormalizeSourcesAllowsOrdinaryProductVersionAndDocumentationPaths(t *testing.T) {
	t.Parallel()

	goodURLs := []string{
		"https://docs.example.com/firmware/v2.4.1",
		"https://docs.example.com/firmware/v10.1.2",
		"https://docs.example.com/firmware/router-v10.1.2",
		"https://docs.example.com/models/model-july-13-2026",
		"https://docs.example.com/docs/2026/router-v2.1.0",
		"https://docs.example.com/kb/1234567",
		"https://2026.docs.example.com/products/ax6000",
		"https://docs.example.com/support/serial-number-guide-2026",
	}
	for _, rawURL := range goodURLs {
		if _, err := NormalizeSources([]Source{{Kind: "vendor_doc", PublicURL: rawURL}}); err != nil {
			t.Errorf("ordinary documentation citation %q rejected: %v", rawURL, err)
		}
	}
}

func TestNormalizeSourcesAndFactsRejectDuplicatesAndPreserveIDs(t *testing.T) {
	t.Parallel()

	citation := Source{Kind: "vendor_doc", PublicURL: "https://docs.example.com/camera"}
	if _, err := NormalizeSources([]Source{citation, citation}); err == nil {
		t.Fatal("duplicate citations unexpectedly accepted")
	}
	retitled := citation
	retitled.Title = "Same citation with another title"
	if _, err := NormalizeSources([]Source{citation, retitled}); err == nil {
		t.Fatal("same citation URL with different metadata unexpectedly accepted")
	}

	fact := VersionFact{
		FactID: testFactID, Attribute: "firmware_version", Relation: "exact",
		Value: "2.4.1", ConfidenceBP: 9000, SourceID: testSourceID,
	}
	got, err := NormalizeVersionFacts([]VersionFact{fact}, nil)
	if err != nil {
		t.Fatalf("valid fact rejected: %v", err)
	}
	if got[0].FactID != fact.FactID || got[0].SourceID != fact.SourceID {
		t.Fatalf("server IDs were not preserved: %#v", got[0])
	}
	duplicate := fact
	duplicate.FactID = testFactID2
	if _, err = NormalizeVersionFacts([]VersionFact{fact, duplicate}, nil); err == nil {
		t.Fatal("repeated version fact unexpectedly accepted")
	}
	duplicate.ConfidenceBP = 8000
	if _, err = NormalizeVersionFacts([]VersionFact{fact, duplicate}, nil); err == nil {
		t.Fatal("repeated fact with conflicting confidence unexpectedly accepted")
	}

	for _, value := range []string{"2.4.%31", "２.４.１", "serial=SN123456", "Serial Number SN123456789"} {
		candidate := fact
		candidate.Value = value
		if _, err = NormalizeVersionFacts([]VersionFact{candidate}, nil); err == nil {
			t.Fatalf("unsafe version value %q unexpectedly accepted", value)
		}
	}
}

func TestNormalizersRejectNonCanonicalServerIDsWithoutEcho(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		marker string
		run    func() error
	}{
		{
			name: "source ID", marker: "alice-office-router",
			run: func() error {
				_, err := NormalizeSources([]Source{{
					SourceID: "alice-office-router", Kind: "vendor_doc",
					PublicURL: "https://docs.example.com/camera",
				}})
				return err
			},
		},
		{
			name: "fact ID", marker: "living-room-firmware",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					FactID: "living-room-firmware", Attribute: "firmware_version",
					Relation: "exact", Value: "2.4.1", SourceID: testSourceID,
				}}, nil)
				return err
			},
		},
		{
			name: "fact source ID", marker: "owner-manual-source",
			run: func() error {
				_, err := NormalizeVersionFacts([]VersionFact{{
					FactID: testFactID, Attribute: "firmware_version", Relation: "exact",
					Value: "2.4.1", SourceID: "owner-manual-source",
				}}, nil)
				return err
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.run()
			if err == nil {
				t.Fatal("non-canonical server ID unexpectedly accepted")
			}
			if strings.Contains(err.Error(), tt.marker) {
				t.Fatalf("ID validation error reflected rejected value: %v", err)
			}
		})
	}
}
