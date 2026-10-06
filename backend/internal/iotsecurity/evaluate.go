package iotsecurity

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	NozomiSource  = "https://www.nozominetworks.com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-"
	RealtekSource = "https://www.realtek.com/images/safe-report/Realtek_APRouter_SDK_Advisory-CVE-2021-35392_35395.pdf"
	Unit42Source  = "https://unit42.paloaltonetworks.com/realtek-sdk-vulnerability/"
)

// These artifact digests were published by Nozomi. No infrastructure addresses
// are included: a public STUN service is not a malicious destination indicator.
var clingSHA256 = map[string]bool{
	"90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2": true,
	"3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28": true,
}

var clingSHA1 = map[string]bool{
	"3b0ac6aaabb3bf8058ca14f9c8ccc613cfa3ea71": true,
	"08636d09d9ffd1713bd6bcb965ad40b6ce3de1aa": true,
}

// Realtek's documented SDK marker can include a source revision, for example
// 3.2.3-r14377. Preserve the full marker in evidence and compare only its SDK
// version. A nominally affected version still cannot rule out an OEM backport.
var sdkVersionPattern = regexp.MustCompile(`(?i)^v?([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?([a-z]?)(?:-r[0-9]{1,10})?$`)

// Evaluate rechecks the observation contract so a future internal caller cannot
// accidentally bypass endpoint validation. Invalid observations produce no
// detector evidence. The HTTP adapter reports validation errors separately.
func Evaluate(observation Observation) []Detection {
	if ValidateObservation(observation) != nil {
		return nil
	}
	switch observation.Kind {
	case KindRealtekExploit:
		return []Detection{{
			Detector: DetectorRealtekExploit, Category: "exploitation_attempt",
			ObservableType: "vulnerability", ObservableValue: "CVE-2021-35394",
			Confidence: 0.90, Score: 0.65,
			Rationale: "An orf; command-injection signature was observed targeting UDP 9034. This is an exploit attempt; successful execution, vulnerable firmware, and device compromise are not established.",
			Details:   map[string]any{"assessment": "exploit_attempt", "cve": "CVE-2021-35394", "protocol": "udp", "port": 9034, "packet_count": len(observation.Packets), "execution_confirmed": false, "sources": []string{RealtekSource, Unit42Source}},
		}}
	case KindSTUNFanout:
		peers := zeroIDPeers(observation.Packets)
		if len(peers) < 3 {
			return nil
		}
		return []Detection{{
			Detector: DetectorSTUNFanout, Category: "suspicious_network_activity",
			ObservableType: "behavior", ObservableValue: "stun_zero_transaction_id_fanout",
			Confidence: 0.45, Score: 0.40,
			Rationale: fmt.Sprintf("Valid STUN Binding Requests with an all-zero transaction ID reached %d distinct peers within 60 seconds. This is suspicious behavior, not proof of Cling or a compromised device; public STUN services remain legitimate.", len(peers)),
			Details:   map[string]any{"assessment": "suspicious_behavior", "distinct_peers": len(peers), "peers": peers, "window_seconds": 60, "minimum_peers": 3, "threshold_source": "vedetta_policy", "compromise_confirmed": false, "sources": []string{NozomiSource, "https://datatracker.ietf.org/doc/html/rfc8489"}},
		}}
	case KindClingRegistration:
		if tag, peer, ok := correlatedRegistration(observation.Packets); ok {
			return []Detection{{
				Detector: DetectorRegistration, Category: "command_and_control",
				ObservableType: "behavior", ObservableValue: "cling_registration_with_zero_id_stun",
				Confidence: 0.80, Score: 0.80,
				Rationale: "A Cling infection-method registration token was observed in non-STUN UDP data, correlated with a zero-transaction-ID Binding Request on the same source, peer and ports within 60 seconds. This supports probable Cling behavior; process execution has not been confirmed.",
				Details:   map[string]any{"assessment": "probable_cling_behavior", "registration_tag": tag, "peer": peer, "window_seconds": 60, "execution_confirmed": false, "sources": []string{NozomiSource}},
			}}
		}
	case KindHostAudit:
		return evaluateAudit(observation)
	}
	return nil
}

func stunPort(port uint16) bool { return port == 3478 || port == 19302 }

func payload(packet PacketEvidence) []byte {
	value, _ := hex.DecodeString(packet.PayloadHex)
	return value
}

// A retained header can establish wire framing without retaining attributes.
// Registration matching rejects every plausible STUN envelope, so an innocent
// USERNAME attribute containing a token cannot masquerade as custom C2 traffic.
func stunEnvelope(packet PacketEvidence) bool {
	value := payload(packet)
	if len(value) < 20 || binary.BigEndian.Uint16(value[:2])&0xc000 != 0 || binary.BigEndian.Uint32(value[4:8]) != 0x2112a442 {
		return false
	}
	length := int(binary.BigEndian.Uint16(value[2:4]))
	return length%4 == 0 && length+20 == packet.PayloadLength
}

func zeroIDBinding(packet PacketEvidence) bool {
	if !stunPort(packet.DestinationPort) || !stunEnvelope(packet) {
		return false
	}
	value := payload(packet)
	return binary.BigEndian.Uint16(value[:2]) == 0x0001 && bytes.Equal(value[8:20], make([]byte, 12))
}

func zeroIDPeers(packets []PacketEvidence) []string {
	peers := make(map[string]bool)
	for _, packet := range packets {
		if zeroIDBinding(packet) {
			peers[net.ParseIP(packet.DestinationIP).String()] = true
		}
	}
	out := make([]string, 0, len(peers))
	for peer := range peers {
		out = append(out, peer)
	}
	sort.Strings(out)
	return out
}

func correlatedRegistration(packets []PacketEvidence) (tag, peer string, ok bool) {
	for _, registration := range packets {
		if !stunPort(registration.DestinationPort) || stunEnvelope(registration) {
			continue
		}
		tag := registrationTag(registration)
		if tag == "" {
			continue
		}
		for _, request := range packets {
			if !zeroIDBinding(request) || request.SourcePort != registration.SourcePort || request.DestinationPort != registration.DestinationPort ||
				!sameIP(request.SourceIP, registration.SourceIP) || !sameIP(request.DestinationIP, registration.DestinationIP) ||
				request.Timestamp.After(registration.Timestamp) {
				continue
			}
			return tag, net.JoinHostPort(net.ParseIP(request.DestinationIP).String(), strconv.Itoa(int(request.DestinationPort))), true
		}
	}
	return "", "", false
}

func registrationTag(packet PacketEvidence) string {
	value := payload(packet)
	for _, token := range []string{"realtek.selfrep", "selfrep.router"} {
		start := 0
		for start < len(value) {
			found := bytes.Index(value[start:], []byte(token))
			if found < 0 {
				break
			}
			found += start
			end := found + len(token)
			left := found == 0 || tokenDelimiter(value[found-1])
			right := end < len(value) && tokenDelimiter(value[end]) || end == len(value) && len(value) == packet.PayloadLength
			if left && right {
				return token
			}
			start = found + 1
		}
	}
	return ""
}

func tokenDelimiter(value byte) bool {
	switch value {
	case 0, ' ', '\t', '\r', '\n', '\v', '\f', ',', ';', ':':
		return true
	default:
		return false
	}
}

func evaluateAudit(observation Observation) []Detection {
	out := []Detection{}
	if sdk := observation.SDK; sdk != nil {
		if sdk.Version == "" {
			out = append(out, sdkDetection(*sdk, "component_requires_verification", 0.35, 0.30,
				"A Realtek Jungle SDK marker and UDPServer component were reported. The SDK version and OEM patch status are unknown. Component presence does not establish that UDPServer is running or reachable; verify CVE-2021-35394 applicability."))
		} else if affectedSDKVersion(sdk.Version) {
			out = append(out, sdkDetection(*sdk, "potentially_affected", 0.65, 0.60,
				"A Realtek Jungle UDPServer component and SDK version within the published CVE-2021-35394 range were reported. The component is potentially affected: OEM backports, patch status, service execution and network reachability remain unverified."))
		}
		// Outside or unparseable versions are unassessed for this CVE. They are
		// never called fixed, clean or known affected by a broad vendor guess.
	}
	artifactIndexes := make(map[string]int)
	files := make(map[string]FileEvidence, len(observation.Files))
	for _, file := range observation.Files {
		files[file.Path] = file
		algorithm, digest := knownArtifact(file)
		if digest == "" {
			continue
		}
		key := algorithm + ":" + digest
		if index, exists := artifactIndexes[key]; exists {
			paths := out[index].Details["paths"].([]string)
			out[index].Details["paths"] = append(paths, file.Path)
			continue
		}
		artifactIndexes[key] = len(out)
		out = append(out, Detection{
			Detector: DetectorArtifact, Category: "malware_artifact",
			ObservableType: "file_" + algorithm, ObservableValue: digest,
			Confidence: 0.99, Score: 0.95,
			Rationale: "A reported file digest matches a published Cling campaign artifact. This identifies a malware artifact in the inspected filesystem; it does not establish that the file executed or that a process is currently running.",
			Details:   map[string]any{"assessment": "confirmed_malware_artifact", "algorithm": algorithm, "digest": digest, "paths": []string{file.Path}, "execution_confirmed": false, "sources": artifactSources(algorithm, digest)},
		})
	}
	seenPersistence := make(map[string]int)
	for _, persistence := range observation.Persistence {
		file, exists := files[persistence.Target]
		if !exists || !file.Executable || !elfFile(file) || !clingBinaryEvidence(file) {
			continue
		}
		if index, exists := seenPersistence[persistence.Target]; exists {
			paths := out[index].Details["init_paths"].([]string)
			out[index].Details["init_paths"] = append(paths, persistence.Path)
			continue
		}
		seenPersistence[persistence.Target] = len(out)
		out = append(out, Detection{
			Detector: DetectorPersistence, Category: "suspected_compromise",
			ObservableType: "file_path", ObservableValue: persistence.Target,
			Confidence: 0.85, Score: 0.80,
			Rationale: "An executable ELF at a documented Cling path contains Cling-specific artifact evidence and is referenced by an init persistence file. This supports probable compromise of the inspected filesystem; current process execution remains unverified.",
			Details:   map[string]any{"assessment": "probable_compromise", "target": persistence.Target, "init_paths": []string{persistence.Path}, "markers": file.Markers, "wget_replacement_artifacts": wgetReplacementPaths(files), "execution_confirmed": false, "sources": persistenceSources(file)},
		})
	}
	for i := range out {
		source := auditSource(observation)
		out[i].Details["audit_source"] = source
		if source != "live_sensor_root" {
			out[i].Details["current_installation"] = "unverified"
			if source == "explicit_filesystem" {
				out[i].Rationale += " The filesystem was explicitly supplied for inspection; whether it is currently installed on this subject is unverified."
			} else {
				out[i].Rationale += " The audit source was not specified; whether this filesystem is currently installed on the subject is unverified."
			}
		} else {
			out[i].Details["current_installation"] = "sensor_host_filesystem"
		}
	}
	return out
}

func auditSource(observation Observation) string {
	for _, coverage := range observation.Coverage {
		if coverage.Check == "audit_source" && coverage.Status == "inspected" && (coverage.Detail == "live_sensor_root" || coverage.Detail == "explicit_filesystem") {
			return coverage.Detail
		}
	}
	return "unknown"
}

func sdkDetection(sdk SDKEvidence, assessment string, confidence, score float64, rationale string) Detection {
	return Detection{
		Detector: DetectorRealtekExposure, Category: "vulnerability_exposure",
		ObservableType: "vulnerability", ObservableValue: "CVE-2021-35394",
		Confidence: confidence, Score: score, Rationale: rationale,
		Details: map[string]any{"assessment": assessment, "cve": "CVE-2021-35394", "component_path": sdk.ComponentPath, "marker_path": sdk.MarkerPath, "family": sdk.Family, "version": sdk.Version, "patch_status": "unknown", "reachability": "unknown", "execution_confirmed": false, "sources": []string{RealtekSource, Unit42Source}},
	}
}

func affectedSDKVersion(value string) bool {
	parts := sdkVersionPattern.FindStringSubmatch(value)
	if parts == nil {
		return false
	}
	major, _ := strconv.Atoi(parts[1])
	minor, _ := strconv.Atoi(parts[2])
	patch, _ := strconv.Atoi(parts[3])
	if major < 2 || major > 3 {
		return false
	}
	if major == 2 || minor < 4 {
		return true
	}
	if minor > 4 || patch > 14 {
		return false
	}
	return patch < 14 || strings.ToUpper(parts[4]) <= "B"
}

func knownArtifact(file FileEvidence) (algorithm, digest string) {
	if digest := strings.ToLower(file.SHA256); clingSHA256[digest] {
		return "sha256", digest
	}
	if digest := strings.ToLower(file.SHA256); clingFortiGuardSHA256[digest] {
		return "sha256", digest
	}
	if digest := strings.ToLower(file.SHA1); clingSHA1[digest] {
		return "sha1", digest
	}
	return "", ""
}

func artifactSources(algorithm, digest string) []string {
	sources := []string{}
	if algorithm == "sha256" && clingSHA256[digest] || algorithm == "sha1" && clingSHA1[digest] {
		sources = append(sources, NozomiSource)
	}
	if algorithm == "sha256" && clingFortiGuardSHA256[digest] {
		sources = append(sources, FortiGuardSource)
	}
	return sources
}

// The persistence technique and binary identity can come from different
// research. Preserve both sources when a known digest supplies the identity.
func persistenceSources(file FileEvidence) []string {
	sources := []string{NozomiSource}
	seen := map[string]bool{NozomiSource: true}
	algorithm, digest := knownArtifact(file)
	for _, source := range artifactSources(algorithm, digest) {
		if !seen[source] {
			sources = append(sources, source)
			seen[source] = true
		}
	}
	return sources
}

func elfFile(file FileEvidence) bool {
	magic, _ := hex.DecodeString(file.MagicHex)
	return len(magic) >= 4 && bytes.Equal(magic[:4], []byte{0x7f, 'E', 'L', 'F'})
}

func clingBinaryEvidence(file FileEvidence) bool {
	if _, digest := knownArtifact(file); digest != "" {
		return true
	}
	markers := make(map[string]bool, len(file.Markers))
	for _, marker := range file.Markers {
		markers[marker] = true
	}
	return markers["User-Agent: clingwashere"] || markers[".selfrep"] && (markers["/.cling"] || markers["mount --bind /tmp /proc/%d"])
}

func wgetReplacementPaths(files map[string]FileEvidence) []string {
	paths := []string{}
	for _, directory := range binaryDirectories {
		base := directory + "/wget"
		if replacement, exists := files[base]; exists && replacement.Executable && elfFile(replacement) {
			_, original := files[base+".r"]
			_, wrapper := files[base+".p"]
			if original && wrapper {
				paths = append(paths, base)
			}
		}
	}
	return paths
}
