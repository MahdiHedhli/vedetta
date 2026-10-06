package iotsecurity

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 10, 6, 20, 0, 0, 0, time.UTC)

func fixtureObservation(kind string) Observation {
	return Observation{ObservationID: "synthetic-observation", Timestamp: fixtureTime, SubjectIP: "192.0.2.10", Kind: kind}
}

func fixturePacket(peer string, value []byte) PacketEvidence {
	return PacketEvidence{Timestamp: fixtureTime, SourceIP: "192.0.2.10", DestinationIP: peer, SourcePort: 42000, DestinationPort: 3478, PayloadHex: hex.EncodeToString(value), PayloadLength: len(value)}
}

func bindingHeader() []byte {
	return []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

func fixtureAudit(version string) Observation {
	observation := fixtureObservation(KindHostAudit)
	observation.Files = []FileEvidence{{Path: "/bin/UDPServer", MagicHex: "7f454c46", Size: 512}, {Path: "/etc/version", Size: 40}}
	observation.SDK = &SDKEvidence{ComponentPath: "/bin/UDPServer", MarkerPath: "/etc/version", Family: "realtek_jungle", Version: version}
	return observation
}

func TestRealtekPrefixIsAttemptAndCommandsAreRejected(t *testing.T) {
	observation := fixtureObservation(KindRealtekExploit)
	packet := fixturePacket(observation.SubjectIP, []byte("orf;"))
	packet.SourceIP, packet.DestinationPort, packet.PayloadLength = "198.51.100.8", 9034, 30
	observation.Packets = []PacketEvidence{packet}
	detections := Evaluate(observation)
	if len(detections) != 1 || detections[0].Detector != DetectorRealtekExploit || detections[0].Details["assessment"] != "exploit_attempt" || detections[0].Details["execution_confirmed"] != false {
		t.Fatalf("attempt classification = %+v", detections)
	}
	observation.Packets[0].PayloadHex = hex.EncodeToString([]byte("orf;synthetic-command"))
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("command-bearing evidence was accepted for persistence")
	}
	if detections := Evaluate(observation); len(detections) != 0 {
		t.Fatalf("invalid payload produced evidence: %+v", detections)
	}
	observation.Packets[0].PayloadHex, observation.Packets[0].PayloadLength = "6f72663b", 4
	if ValidateObservation(observation) == nil || len(Evaluate(observation)) != 0 {
		t.Fatal("bare prefix without a command was classified as an exploit attempt")
	}
}

func TestSTUNFanoutRequiresValidRequestsAndDistinctPeers(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Observation)
		want   bool
	}{
		{name: "three zero ID request peers", want: true},
		{name: "one isolated zero ID request", modify: func(o *Observation) { o.Packets = o.Packets[:1] }},
		{name: "same peer with different ports", modify: func(o *Observation) {
			for i := range o.Packets {
				o.Packets[i].DestinationIP = "198.51.100.1"
				o.Packets[i].SourcePort += uint16(i)
			}
		}},
		{name: "responses echoing zero ID", modify: func(o *Observation) {
			for i := range o.Packets {
				value := bindingHeader()
				value[0] = 1
				o.Packets[i].PayloadHex = hex.EncodeToString(value)
			}
		}},
		{name: "ordinary random transaction IDs", modify: func(o *Observation) {
			for i := range o.Packets {
				value := bindingHeader()
				value[8] = byte(i + 1)
				o.Packets[i].PayloadHex = hex.EncodeToString(value)
			}
		}},
		{name: "bad magic cookie", modify: func(o *Observation) {
			for i := range o.Packets {
				value := bindingHeader()
				value[4] = 0
				o.Packets[i].PayloadHex = hex.EncodeToString(value)
			}
		}},
		{name: "declared UDP length mismatch", modify: func(o *Observation) {
			for i := range o.Packets {
				o.Packets[i].PayloadLength = 24
			}
		}},
		{name: "short retained header", modify: func(o *Observation) {
			for i := range o.Packets {
				o.Packets[i].PayloadHex = o.Packets[i].PayloadHex[:38]
			}
		}},
		{name: "subject mismatch", modify: func(o *Observation) { o.Packets[0].SourceIP = "192.0.2.11" }},
		{name: "outside correlation window", modify: func(o *Observation) { o.Packets[0].Timestamp = fixtureTime.Add(-61 * time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := fixtureObservation(KindSTUNFanout)
			for _, peer := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
				observation.Packets = append(observation.Packets, fixturePacket(peer, bindingHeader()))
			}
			if test.modify != nil {
				test.modify(&observation)
			}
			detections := Evaluate(observation)
			if (len(detections) == 1) != test.want {
				t.Fatalf("detections = %+v", detections)
			}
			if test.want && (detections[0].Detector != DetectorSTUNFanout || detections[0].Details["compromise_confirmed"] != false) {
				t.Fatalf("overclaimed STUN result: %+v", detections)
			}
		})
	}
}

func TestRegistrationRequiresNonSTUNTagAndSameFlow(t *testing.T) {
	tests := []struct {
		name   string
		value  []byte
		modify func(*Observation)
		want   bool
	}{
		{name: "Realtek infection token", value: []byte("realtek.selfrep"), want: true},
		{name: "router token with delimiters", value: []byte("x\x00selfrep.router\x00y"), want: true},
		{name: "suffix is not exact token", value: []byte("prefix-realtek.selfrep-suffix")},
		{name: "unknown token", value: []byte("selfrep.other")},
		{name: "tag without request", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets = o.Packets[1:] }},
		{name: "different source port", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets[1].SourcePort++ }},
		{name: "different peer", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets[1].DestinationIP = "198.51.100.2" }},
		{name: "different destination port", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets[1].DestinationPort = 19302 }},
		{name: "registration before request", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets[1].Timestamp = fixtureTime.Add(-time.Second) }},
		{name: "request before registration", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets[0].Timestamp = fixtureTime.Add(-time.Second) }, want: true},
		{name: "truncated token boundary", value: []byte("realtek.selfrep"), modify: func(o *Observation) { o.Packets[1].PayloadLength = 200 }},
		{name: "token inside valid STUN attribute", value: usernameSTUN()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := fixtureObservation(KindClingRegistration)
			observation.Packets = []PacketEvidence{fixturePacket("198.51.100.1", bindingHeader()), fixturePacket("198.51.100.1", test.value)}
			if test.modify != nil {
				test.modify(&observation)
			}
			detections := Evaluate(observation)
			if (len(detections) == 1) != test.want {
				t.Fatalf("detections = %+v", detections)
			}
		})
	}
}

func usernameSTUN() []byte {
	value := bindingHeader()
	value = append(value, 0, 6, 0, 14)
	value = append(value, []byte("realtek.selfrep")...)
	value = append(value, 0, 0)
	binary.BigEndian.PutUint16(value[2:4], uint16(len(value)-20))
	return value
}

func TestSDKVersionsRemainPotentialAndOutsideRangeUnassessed(t *testing.T) {
	for _, test := range []struct{ version, assessment string }{
		{"2.0", "potentially_affected"}, {"3.4.14B", "potentially_affected"}, {"v3.4.14b", "potentially_affected"},
		{"3.2.3", "potentially_affected"}, {"3.2.3-r14377", "potentially_affected"}, {"3.4.11E", "potentially_affected"}, {"3.4T", "potentially_affected"},
		{"", "component_requires_verification"}, {"3.4.14C", ""}, {"3.4.15", ""}, {"1.3.1", ""}, {"4.0", ""}, {"6.1.12 Linux", ""},
	} {
		t.Run(test.version, func(t *testing.T) {
			observation := fixtureAudit(test.version)
			detections := Evaluate(observation)
			if test.assessment == "" {
				if len(detections) != 0 {
					t.Fatalf("outside/unknown version asserted affected: %+v", detections)
				}
				return
			}
			if len(detections) != 1 || detections[0].Details["assessment"] != test.assessment || detections[0].Details["patch_status"] != "unknown" || detections[0].Details["reachability"] != "unknown" {
				t.Fatalf("SDK result = %+v", detections)
			}
		})
	}
	observation := fixtureAudit("3.4.14B")
	observation.Files = nil
	if ValidateObservation(observation) == nil || len(Evaluate(observation)) != 0 {
		t.Fatal("unbacked SDK assertion accepted")
	}
	observation = fixtureAudit("3.4.14B")
	observation.SDK.Family = "Realtek OUI"
	if ValidateObservation(observation) == nil || len(Evaluate(observation)) != 0 {
		t.Fatal("vendor-only evidence accepted as SDK evidence")
	}
}

func TestPublishedDigestsAreArtifactsNotExecution(t *testing.T) {
	for _, file := range []FileEvidence{
		{Path: "/root/.cling", Size: 512, SHA1: "3b0ac6aaabb3bf8058ca14f9c8ccc613cfa3ea71"},
		{Path: "/root/.cling", Size: 512, SHA1: "08636d09d9ffd1713bd6bcb965ad40b6ce3de1aa"},
		{Path: "/root/.cling", Size: 512, SHA256: "90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2"},
		{Path: "/root/.cling", Size: 512, SHA256: "3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28"},
	} {
		observation := fixtureObservation(KindHostAudit)
		observation.Files = []FileEvidence{file}
		detections := Evaluate(observation)
		if len(detections) != 1 || detections[0].Detector != DetectorArtifact || detections[0].Details["execution_confirmed"] != false {
			t.Fatalf("artifact result = %+v", detections)
		}
	}
}

func TestExplicitFilesystemAuditDoesNotAssertCurrentInstallation(t *testing.T) {
	observation := fixtureAudit("3.4.14B")
	observation.Files = append(observation.Files, FileEvidence{Path: "/root/.cling", Size: 512, SHA256: "90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2"})
	observation.Coverage = []Coverage{{Check: "audit_source", Status: "inspected", Detail: "explicit_filesystem"}}
	detections := Evaluate(observation)
	if len(detections) != 2 {
		t.Fatalf("audit findings = %+v", detections)
	}
	for _, detection := range detections {
		if detection.Details["audit_source"] != "explicit_filesystem" || detection.Details["current_installation"] != "unverified" || !strings.Contains(detection.Rationale, "currently installed") {
			t.Fatalf("explicit firmware audit presented as installed: %+v", detection)
		}
	}
}

func TestFortiGuardArtifactRetainsItsSource(t *testing.T) {
	const digest = "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a"
	observation := fixtureObservation(KindHostAudit)
	observation.Files = []FileEvidence{{Path: "/root/.cling", Size: 512, SHA256: digest}}
	detections := Evaluate(observation)
	if len(detections) != 1 || detections[0].Detector != DetectorArtifact {
		t.Fatalf("FortiGuard result = %+v", detections)
	}
	sources := detections[0].Details["sources"].([]string)
	if len(sources) != 1 || sources[0] != FortiGuardSource {
		t.Fatalf("FortiGuard source = %v", sources)
	}
	if !strings.Contains(detections[0].Rationale, "published Cling campaign artifact") {
		t.Fatalf("campaign artifact rationale = %q", detections[0].Rationale)
	}
}

func TestPersistenceRetainsSupportingResearchSources(t *testing.T) {
	for _, test := range []struct {
		name   string
		digest string
		want   []string
	}{
		{"FortiGuard binary and Nozomi persistence", "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a", []string{NozomiSource, FortiGuardSource}},
		{"Nozomi binary and persistence deduplicated", "90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2", []string{NozomiSource}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := fixtureObservation(KindHostAudit)
			// No string markers: the published digest is the only binary-identity
			// proof, so omitting its source would lose material provenance.
			observation.Files = []FileEvidence{{Path: "/root/.cling", Size: 512, SHA256: test.digest, MagicHex: "7f454c46", Executable: true}}
			observation.Persistence = []PersistenceEvidence{{Path: "/etc/inittab", Target: "/root/.cling"}}
			detections := Evaluate(observation)
			found := false
			for _, detection := range detections {
				if detection.Detector != DetectorPersistence {
					continue
				}
				found = true
				sources := detection.Details["sources"].([]string)
				if len(sources) != len(test.want) || strings.Join(sources, "\n") != strings.Join(test.want, "\n") {
					t.Fatalf("persistence sources = %v, want %v", sources, test.want)
				}
			}
			if !found {
				t.Fatalf("missing persistence evidence: %+v", detections)
			}
		})
	}
}

func TestPersistenceRequiresCorroboratedExecutable(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Observation)
		want   bool
	}{
		{name: "ELF markers and matching init", want: true},
		{name: "filename and ELF alone", modify: func(o *Observation) { o.Files[0].Markers = nil }},
		{name: "markers without persistence", modify: func(o *Observation) { o.Persistence = nil }},
		{name: "different init target", modify: func(o *Observation) { o.Persistence[0].Target = "/usr/local/bin/.cling" }},
		{name: "not executable", modify: func(o *Observation) { o.Files[0].Executable = false }},
		{name: "script instead of ELF", modify: func(o *Observation) { o.Files[0].MagicHex = "23212f62" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := fixtureObservation(KindHostAudit)
			observation.Files = []FileEvidence{{Path: "/root/.cling", Size: 512, MagicHex: "7f454c46", Executable: true, Markers: []string{".selfrep", "/.cling"}}}
			observation.Persistence = []PersistenceEvidence{{Path: "/etc/inittab", Target: "/root/.cling"}}
			if test.modify != nil {
				test.modify(&observation)
			}
			detections := Evaluate(observation)
			if (len(detections) == 1) != test.want {
				t.Fatalf("persistence result = %+v", detections)
			}
		})
	}
	observation := fixtureObservation(KindHostAudit)
	observation.Files = []FileEvidence{{Path: "/bin/wget", Size: 512, MagicHex: "7f454c46", Executable: true}, {Path: "/bin/wget.r", Size: 512}, {Path: "/bin/wget.p", Size: 128}}
	if detections := Evaluate(observation); len(detections) != 0 {
		t.Fatalf("wget triad alone overclaimed compromise: %+v", detections)
	}
}

func TestValidationBoundsAndCoverage(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Observation)
	}{
		{"path traversal", func(o *Observation) { o.Files[0].Path = "/root/../root/.cling" }},
		{"unlisted path", func(o *Observation) { o.Files[0].Path = "/etc/shadow" }},
		{"invalid digest", func(o *Observation) { o.Files[0].SHA256 = strings.Repeat("z", 64) }},
		{"oversized marker", func(o *Observation) { o.Files[0].Markers = []string{strings.Repeat("x", 129)} }},
		{"magic longer than file", func(o *Observation) { o.Files[0].Size = 1; o.Files[0].MagicHex = "7f454c46" }},
		{"no subject", func(o *Observation) { o.SubjectIP = "" }},
		{"subject is hostname", func(o *Observation) { o.SubjectIP = "router.example" }},
		{"zero timestamp", func(o *Observation) { o.Timestamp = time.Time{} }},
		{"arbitrary coverage status", func(o *Observation) { o.Coverage = []Coverage{{Check: "audit", Status: "clean"}} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := fixtureObservation(KindHostAudit)
			observation.Files = []FileEvidence{{Path: "/root/.cling", Size: 512}}
			test.modify(&observation)
			if err := ValidateObservation(observation); err == nil {
				t.Fatal("malformed observation accepted")
			}
		})
	}
	observation := fixtureObservation(KindCoverage)
	observation.Coverage = []Coverage{{Check: "passive_udp", Status: "unavailable", Detail: "No capture interface; not assessed."}}
	if err := ValidateObservation(observation); err != nil {
		t.Fatal(err)
	}
	if len(Evaluate(observation)) != 0 {
		t.Fatal("coverage created a security verdict")
	}
	if err := ValidateBatch([]Observation{observation, observation}); err == nil {
		t.Fatal("duplicate IDs within a batch accepted")
	}
	if err := ValidateBatch(make([]Observation, MaxBatchObservations+1)); err == nil {
		t.Fatal("oversized batch accepted")
	}
}
