package iotsecurity

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

var observationIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

var binaryDirectories = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"}

var clingPaths = map[string]bool{
	"/root/.cling": true, "/usr/local/bin/.cling": true,
}

var initPaths = map[string]bool{
	"/etc/inittab": true, "/etc/init.d/rcS": true, "/etc/rc.d/rc.boot": true,
}

var sdkMarkerPaths = map[string]bool{"/etc/version": true, "/etc/motd": true}

var binaryMarkers = map[string]bool{
	".selfrep": true, "/.cling": true,
	"User-Agent: clingwashere": true, "mount --bind /tmp /proc/%d": true,
}

var coverageStatuses = map[string]bool{
	"complete": true, "partial": true, "error": true, "unsupported": true,
	"skipped": true, "not_found": true, "active": true, "unavailable": true,
	"disabled": true, "limited": true, "inspected": true, "absent": true,
}

func componentPath(value string) bool {
	for _, directory := range binaryDirectories {
		if value == directory+"/UDPServer" {
			return true
		}
	}
	return false
}

func auditPath(value string) bool {
	if clingPaths[value] || initPaths[value] || sdkMarkerPaths[value] || componentPath(value) {
		return true
	}
	for _, directory := range binaryDirectories {
		for _, name := range []string{"wget", "wget.r", "wget.p"} {
			if value == directory+"/"+name {
				return true
			}
		}
	}
	return false
}

// ValidateBatch rejects all malformed observations before an adapter performs
// any event write. Observation IDs are occurrence boundaries within a sensor.
func ValidateBatch(observations []Observation) error {
	if len(observations) > MaxBatchObservations {
		return fmt.Errorf("at most %d observations are allowed", MaxBatchObservations)
	}
	seen := make(map[string]bool, len(observations))
	for i, observation := range observations {
		if err := ValidateObservation(observation); err != nil {
			return fmt.Errorf("observation %d: %w", i, err)
		}
		if seen[observation.ObservationID] {
			return fmt.Errorf("observation %d repeats an observation_id within the batch", i)
		}
		seen[observation.ObservationID] = true
	}
	return nil
}

func ValidateObservation(observation Observation) error {
	if !observationIDPattern.MatchString(observation.ObservationID) {
		return fmt.Errorf("observation_id must contain 1 to 128 letters, digits, hyphens or underscores")
	}
	if observation.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if !validIP(observation.SubjectIP) {
		return fmt.Errorf("subject_ip must be a concrete IP address")
	}
	if len(observation.Packets) > MaxPackets || len(observation.Files) > MaxFiles ||
		len(observation.Persistence) > MaxPersistence || len(observation.Coverage) > MaxCoverage {
		return fmt.Errorf("observation exceeds evidence limits")
	}
	packetKind := observation.Kind == KindRealtekExploit || observation.Kind == KindSTUNFanout || observation.Kind == KindClingRegistration
	switch {
	case packetKind:
		if len(observation.Packets) == 0 || len(observation.Files) != 0 || len(observation.Persistence) != 0 || observation.SDK != nil {
			return fmt.Errorf("packet observation requires packets and cannot contain filesystem evidence")
		}
	case observation.Kind == KindHostAudit:
		if len(observation.Packets) != 0 {
			return fmt.Errorf("host audit cannot contain packet evidence")
		}
	case observation.Kind == KindCoverage:
		if len(observation.Packets) != 0 || len(observation.Files) != 0 || len(observation.Persistence) != 0 || observation.SDK != nil || len(observation.Coverage) == 0 {
			return fmt.Errorf("coverage observation requires only coverage entries")
		}
	default:
		return fmt.Errorf("unsupported observation kind")
	}
	for i, packet := range observation.Packets {
		if err := validatePacket(observation, packet); err != nil {
			return fmt.Errorf("packet %d: %w", i, err)
		}
	}
	seenFiles := make(map[string]bool, len(observation.Files))
	for i, file := range observation.Files {
		if !auditPath(file.Path) || seenFiles[file.Path] {
			return fmt.Errorf("file %d: path is unsupported or repeated", i)
		}
		seenFiles[file.Path] = true
		if file.Size < 0 || file.Size > 8<<20 {
			return fmt.Errorf("file %d: size exceeds audited file limit", i)
		}
		if !optionalDigest(file.SHA1, 20) || !optionalDigest(file.SHA256, 32) {
			return fmt.Errorf("file %d: invalid digest", i)
		}
		magic, err := hex.DecodeString(file.MagicHex)
		if err != nil || len(magic) > 16 || int64(len(magic)) > file.Size {
			return fmt.Errorf("file %d: invalid file magic", i)
		}
		if len(file.Markers) > len(binaryMarkers) {
			return fmt.Errorf("file %d: too many markers", i)
		}
		seenMarkers := make(map[string]bool)
		for _, marker := range file.Markers {
			if !binaryMarkers[marker] || seenMarkers[marker] {
				return fmt.Errorf("file %d: unsupported or repeated marker", i)
			}
			seenMarkers[marker] = true
		}
	}
	seenPersistence := make(map[string]bool)
	for i, persistence := range observation.Persistence {
		key := persistence.Path + "\x00" + persistence.Target
		if !initPaths[persistence.Path] || !clingPaths[persistence.Target] || seenPersistence[key] {
			return fmt.Errorf("persistence %d: unsupported or repeated path/target", i)
		}
		seenPersistence[key] = true
	}
	if sdk := observation.SDK; sdk != nil {
		if !componentPath(sdk.ComponentPath) || !sdkMarkerPaths[sdk.MarkerPath] || sdk.Family != "realtek_jungle" || !boundedText(sdk.Version, 64) {
			return fmt.Errorf("invalid SDK evidence")
		}
		componentObserved := false
		for _, file := range observation.Files {
			if file.Path == sdk.ComponentPath && elfFile(file) {
				componentObserved = true
			}
		}
		if !componentObserved || !seenFiles[sdk.MarkerPath] {
			return fmt.Errorf("SDK evidence requires an inspected ELF component and marker file")
		}
	}
	auditSourceSeen := false
	for i, coverage := range observation.Coverage {
		if coverage.Check == "" || !boundedText(coverage.Check, 128) || !coverageStatuses[coverage.Status] || !boundedText(coverage.Detail, 512) {
			return fmt.Errorf("coverage %d: invalid check, status or detail", i)
		}
		if coverage.Check == "audit_source" {
			if auditSourceSeen || observation.Kind != KindHostAudit || coverage.Status != "inspected" || (coverage.Detail != "live_sensor_root" && coverage.Detail != "explicit_filesystem") {
				return fmt.Errorf("coverage %d: invalid or repeated audit source", i)
			}
			auditSourceSeen = true
		}
	}
	return nil
}

func validatePacket(observation Observation, packet PacketEvidence) error {
	if packet.Timestamp.IsZero() || packet.Timestamp.After(observation.Timestamp) || packet.Timestamp.Before(observation.Timestamp.Add(-CorrelationWindow)) {
		return fmt.Errorf("timestamp must be within the preceding 60-second observation window")
	}
	if !validIP(packet.SourceIP) || !validIP(packet.DestinationIP) || packet.DestinationPort == 0 {
		return fmt.Errorf("invalid packet endpoint")
	}
	payload, err := hex.DecodeString(packet.PayloadHex)
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes || packet.PayloadLength < len(payload) || packet.PayloadLength > 65527 {
		return fmt.Errorf("invalid bounded UDP payload")
	}
	if observation.Kind == KindRealtekExploit {
		if !sameIP(observation.SubjectIP, packet.DestinationIP) {
			return fmt.Errorf("Realtek subject must be the packet destination")
		}
		// Never persist attacker-supplied shell commands. The sensor sends only
		// this four-byte signature while retaining the original UDP length.
		if string(payload) != "orf;" || packet.DestinationPort != 9034 || packet.PayloadLength <= 4 {
			return fmt.Errorf("Realtek evidence must contain only the orf; prefix on UDP 9034 with additional uncaptured payload")
		}
	} else if !sameIP(observation.SubjectIP, packet.SourceIP) {
		return fmt.Errorf("STUN subject must be the packet source")
	}
	return nil
}

func optionalDigest(value string, bytes int) bool {
	if value == "" {
		return true
	}
	if len(value) != bytes*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validIP(value string) bool {
	if strings.TrimSpace(value) != value || len(value) > 45 {
		return false
	}
	ip := net.ParseIP(value)
	return ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Equal(net.IPv4bcast)
}

func sameIP(a, b string) bool {
	return net.ParseIP(a).Equal(net.ParseIP(b))
}

func boundedText(value string, maximum int) bool {
	return len(value) <= maximum && strings.IndexFunc(value, unicode.IsControl) < 0
}
