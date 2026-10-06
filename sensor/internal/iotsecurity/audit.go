package iotsecurity

import (
	"bytes"
	"crypto/sha1" // Recorded for matching published legacy sample indicators only.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	maxAuditBinarySize = 8 << 20
	maxAuditTextSize   = 64 << 10
)

var (
	auditBinaryDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"}
	clingPaths      = []string{"/root/.cling", "/usr/local/bin/.cling"}
	initPaths       = []string{"/etc/inittab", "/etc/init.d/rcS", "/etc/rc.d/rc.boot"}
	sdkPaths        = []string{"/etc/version", "/etc/motd"}
	fileMarkers     = []string{".selfrep", "/.cling", "User-Agent: clingwashere", "mount --bind /tmp /proc/%d"}
	sdkVersionRE    = regexp.MustCompile(`(?i)realtek[ \t]+(?:jungle[ \t]+)?sdk[ \t]*(?:version[ \t]*)?[:=]?[ \t]*v?([0-9][0-9a-zA-Z.+_-]{0,63})`)
	jungleMarkerRE  = regexp.MustCompile(`(?i)\brealtek[ \t]+jungle[ \t]+sdk\b`)
	initCommandRE   = regexp.MustCompile(`^[ \t]*(?:(?:exec|nohup|setsid)[ \t]+)?["']?(/root/\.cling|/usr/local/bin/\.cling)["']?(?:[ \t]|$)`)
	functionDefRE   = regexp.MustCompile(`^[ \t]*(?:function[ \t]+|[a-zA-Z_][a-zA-Z_0-9]*[ \t]*\([ \t]*\)[ \t]*\{)`)
)

type auditPath struct {
	name string
	kind string
}

// Audit inspects a fixed set of files beneath root without executing or changing
// any file. An empty subject is allowed for local output; Core submission requires
// an explicitly supplied/local sensor IP. A firmware filesystem's contents alone
// do not establish that its services are running, reachable, or unpatched.
func Audit(root string, subjectIP string) (Observation, error) {
	if strings.TrimSpace(root) == "" {
		return Observation{}, fmt.Errorf("an explicit audit filesystem root is required")
	}
	if subjectIP != "" {
		ip := net.ParseIP(subjectIP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return Observation{}, fmt.Errorf("audit subject must be a concrete IP address")
		}
		subjectIP = ip.String()
	}
	observation := newObservation(time.Now(), subjectIP, "host_audit", nil)
	auditRoot, err := os.OpenRoot(root)
	if err != nil {
		observation.Coverage = []Coverage{{Check: "filesystem_audit", Status: "error", Detail: "could not open the selected filesystem root"}}
		return observation, fmt.Errorf("open audit filesystem root: %w", err)
	}
	defer auditRoot.Close()

	var component string
	var sdkMarker, sdkVersion string
	partial := false
	if runtime.GOOS == "windows" {
		partial = true
		observation.Coverage = append(observation.Coverage, Coverage{
			Check: "unix_execute_permissions", Status: "unsupported",
			Detail: "Unix execute permissions are unavailable on Windows; executable eligibility and persistence based on markers are unassessed; hashes and fixed-path evidence remain available",
		})
	}
	for _, candidate := range auditPaths() {
		limit := int64(maxAuditBinarySize)
		if candidate.kind == "init" || candidate.kind == "sdk" || candidate.kind == "pointer" {
			limit = maxAuditTextSize
		}
		data, info, status, detail := readAuditFile(auditRoot, candidate.name, limit)
		observation.Coverage = append(observation.Coverage, Coverage{Check: candidate.name, Status: status, Detail: detail})
		if status != "complete" {
			if status != "not_found" {
				partial = true
			}
			continue
		}
		file := describeFile(candidate.name, data, info)
		observation.Files = append(observation.Files, file)
		switch candidate.kind {
		case "component":
			if component == "" && bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
				component = candidate.name
			}
		case "sdk":
			if version, found := sdkMarkerVersion(data); found && sdkMarker == "" {
				sdkMarker, sdkVersion = candidate.name, version
			}
		case "init":
			if !simplePersistenceScript(data) {
				partial = true
				observation.Coverage = append(observation.Coverage, Coverage{
					Check: "persistence:" + candidate.name, Status: "partial",
					Detail: "complex shell quoting, function definitions or heredocs were not interpreted as persistence",
				})
				continue
			}
			for _, target := range persistenceTargets(data, candidate.name == "/etc/inittab") {
				observation.Persistence = append(observation.Persistence, PersistenceEvidence{Path: candidate.name, Target: target})
			}
		}
	}
	if component != "" && sdkMarker != "" {
		observation.SDK = &SDKEvidence{
			ComponentPath: component, MarkerPath: sdkMarker, Family: "realtek_jungle", Version: sdkVersion,
		}
		observation.Coverage = append(observation.Coverage, Coverage{
			Check: "realtek_sdk", Status: "partial",
			Detail: "component and SDK marker observed; OEM patch status, service execution and network exposure are unknown",
		})
	}
	status := "complete"
	if partial {
		status = "partial"
	}
	observation.Coverage = append(observation.Coverage, Coverage{
		Check: "filesystem_audit", Status: status,
		Detail: "fixed paths in the selected root only; absence of indicators does not establish a clean device or inspect other LAN devices",
	})
	return observation, nil
}

func auditPaths() []auditPath {
	paths := make([]auditPath, 0, 27)
	for _, name := range clingPaths {
		paths = append(paths, auditPath{name, "binary"})
	}
	for _, dir := range auditBinaryDirs {
		paths = append(paths, auditPath{dir + "/wget", "binary"}, auditPath{dir + "/wget.r", "binary"}, auditPath{dir + "/wget.p", "pointer"})
	}
	for _, dir := range auditBinaryDirs {
		paths = append(paths, auditPath{dir + "/UDPServer", "component"})
	}
	for _, name := range sdkPaths {
		paths = append(paths, auditPath{name, "sdk"})
	}
	for _, name := range initPaths {
		paths = append(paths, auditPath{name, "init"})
	}
	return paths
}

func readAuditFile(root *os.Root, name string, limit int64) ([]byte, fs.FileInfo, string, string) {
	relative := strings.TrimPrefix(name, "/")
	parts := strings.Split(relative, "/")
	// Refuse symlinks even when they would stay inside the root. Root provides
	// race-resistant confinement; this explicit policy also avoids resolving
	// extracted firmware's absolute BusyBox links on the analysis host.
	for index := range parts {
		component := path.Join(parts[:index+1]...)
		info, err := root.Lstat(component)
		if err != nil {
			status, detail := auditReadError(err)
			return nil, nil, status, detail
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, "skipped", "symbolic link omitted; target was not inspected"
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, nil, "skipped", "path component is not a directory"
		}
		if index == len(parts)-1 {
			if !info.Mode().IsRegular() {
				return nil, nil, "skipped", "non-regular file omitted"
			}
			if info.Size() > limit {
				return nil, nil, "skipped", "file exceeds the bounded audit size limit"
			}
		}
	}
	before, err := root.Lstat(relative)
	if err != nil {
		status, detail := auditReadError(err)
		return nil, nil, status, detail
	}
	file, err := openAuditFile(root, relative)
	if err != nil {
		status, detail := auditReadError(err)
		return nil, nil, status, detail
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, "error", "could not inspect the opened file"
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, nil, "skipped", "file type or identity changed during inspection"
	}
	if info.Size() > limit {
		return nil, nil, "skipped", "file exceeds the bounded audit size limit"
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, nil, "error", "could not read the inspected file"
	}
	if int64(len(data)) > limit {
		return nil, nil, "skipped", "file grew beyond the bounded audit size limit"
	}
	after, err := file.Stat()
	if err != nil || int64(len(data)) != info.Size() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, nil, "error", "file changed while being inspected; digest omitted"
	}
	return data, info, "complete", "bounded regular file inspected without execution"
}

func auditReadError(err error) (string, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "not_found", "path not present in selected root"
	case errors.Is(err, fs.ErrPermission):
		return "error", "permission denied; path not inspected"
	default:
		return "error", "path could not be read safely"
	}
}

func describeFile(name string, data []byte, info fs.FileInfo) FileEvidence {
	sha256sum, sha1sum := sha256.Sum256(data), sha1.Sum(data)
	evidence := FileEvidence{
		Path: name, SHA256: hex.EncodeToString(sha256sum[:]), SHA1: hex.EncodeToString(sha1sum[:]),
		Size: int64(len(data)), MagicHex: hex.EncodeToString(data[:min(len(data), 4)]),
		Executable: runtime.GOOS != "windows" && info.Mode()&0o111 != 0,
	}
	for _, marker := range fileMarkers {
		if bytes.Contains(data, []byte(marker)) {
			evidence.Markers = append(evidence.Markers, marker)
		}
	}
	return evidence
}

func sdkMarkerVersion(data []byte) (string, bool) {
	match := sdkVersionRE.FindSubmatch(data)
	if len(match) > 1 {
		version := string(match[1])
		// Generic SDK branding alone is not evidence for every Realtek product.
		// The 2.x/3.x marker is documented for this family. An explicit Jungle
		// marker can carry an unknown/newer version for Core to evaluate.
		if strings.HasPrefix(version, "2.") || strings.HasPrefix(version, "3.") || jungleMarkerRE.Match(data) {
			return version, true
		}
	}
	if jungleMarkerRE.Match(data) {
		return "", true
	}
	return "", false
}

func persistenceTargets(data []byte, inittab bool) []string {
	if !simplePersistenceScript(data) {
		return nil
	}
	found := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(stripShellComment(line))
		if line == "" {
			continue
		}
		if inittab {
			fields := strings.SplitN(line, ":", 4)
			if len(fields) != 4 {
				continue
			}
			line = fields[3]
		}
		for _, command := range splitShellCommands(line) {
			if match := initCommandRE.FindStringSubmatch(command); len(match) > 1 {
				found[match[1]] = true
			}
		}
	}
	var targets []string
	for _, target := range clingPaths {
		if found[target] {
			targets = append(targets, target)
		}
	}
	return targets
}

// We intentionally do not interpret complete shell programs. Multiline strings,
// heredocs and uncalled function bodies can contain command-looking literals.
// If encountered, leave persistence unassessed instead of turning those literals
// into evidence that a boot script invokes the malware.
func simplePersistenceScript(data []byte) bool {
	for _, original := range strings.Split(string(data), "\n") {
		line := stripShellComment(original)
		if functionDefRE.MatchString(line) {
			return false
		}
		var quote byte
		escaped := false
		for index := 0; index < len(line); index++ {
			value := line[index]
			if escaped {
				escaped = false
				continue
			}
			if value == '\\' && quote != '\'' {
				escaped = true
				continue
			}
			if quote != 0 {
				if value == quote {
					quote = 0
				}
				continue
			}
			if value == '\'' || value == '"' {
				quote = value
				continue
			}
			if value == '<' && index+1 < len(line) && line[index+1] == '<' {
				return false
			}
		}
		if quote != 0 || escaped {
			return false
		}
	}
	return true
}

// splitShellCommands recognizes only unquoted shell separators. Strings printed
// by echo/printf must not become persistence just because they contain a semicolon
// followed by a suspicious pathname. This deliberately does not evaluate shell
// variables, substitutions, wrappers, or arbitrary shell syntax.
func splitShellCommands(line string) []string {
	var commands []string
	var quote byte
	escaped, start := false, 0
	for index := 0; index < len(line); index++ {
		value := line[index]
		if escaped {
			escaped = false
			continue
		}
		if value == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		if value == ';' || value == '&' || value == '|' {
			commands = append(commands, line[start:index])
			start = index + 1
		}
	}
	commands = append(commands, line[start:])
	return commands
}

func stripShellComment(line string) string {
	var quote byte
	escaped := false
	for index := 0; index < len(line); index++ {
		value := line[index]
		if escaped {
			escaped = false
			continue
		}
		if value == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		if value == '#' && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t' || strings.ContainsRune(";&|", rune(line[index-1]))) {
			return line[:index]
		}
	}
	return line
}
