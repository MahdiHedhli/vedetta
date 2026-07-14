//go:build !windows

package netscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// A network scan is external work and must never hold the sensor open forever.
	// Four minutes leaves room for a modest port scan while remaining below the
	// default five-minute sensor interval.
	defaultScanTimeout = 4 * time.Minute

	// Nmap XML is attacker-influenced network data. Keep enough room for a large
	// home/SMB subnet, but never let a noisy or replaced child exhaust the root
	// sensor's memory.
	defaultMaxNmapStdout = int64(32 << 20)
	defaultMaxNmapStderr = int64(1 << 20)

	childWaitDelay    = 2 * time.Second
	selfCheckTimeout  = 3 * time.Second
	portScanBatchSize = 256
)

var minimalNmapEnvironment = []string{
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	"HOME=/var/empty",
	"LANG=C",
	"LC_ALL=C",
}

// ScanResult and DiscoveredHost are defined in types.go (shared across backends).

// Scanner wraps nmap execution.
type Scanner struct {
	BinaryPath string

	credential                  *syscall.Credential
	privilegedDiscoveryEligible bool
	localNetworks               func() ([]net.IPNet, error)
	neighborSnapshot            func(context.Context) (map[string]string, error)
	timeout                     time.Duration
	maxStdout                   int64
	maxStderr                   int64
}

// NewScanner creates a Scanner, verifying nmap is available.
func NewScanner() (*Scanner, error) {
	configuredPath := strings.TrimSpace(os.Getenv("VEDETTA_NMAP_PATH"))
	if configuredPath != "" && !filepath.IsAbs(configuredPath) {
		return nil, fmt.Errorf("VEDETTA_NMAP_PATH must be absolute: %q", configuredPath)
	}

	lookup := configuredPath
	if lookup == "" {
		// Retain PATH lookup for an interactive, non-service invocation. The
		// installer pins VEDETTA_NMAP_PATH for the service so its trust decision is
		// explicit and does not depend on a mutable service PATH.
		lookup = "nmap"
	}
	path, err := exec.LookPath(lookup)
	if err != nil {
		if configuredPath != "" {
			return nil, fmt.Errorf("configured nmap unavailable at %q: %w", configuredPath, err)
		}
		return nil, fmt.Errorf("nmap not found in PATH: %w", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute nmap path: %w", err)
	}
	path, err = canonicalExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("validate nmap executable: %w", err)
	}

	credential, err := nmapCredential(os.Geteuid(), runtime.GOOS, user.Lookup)
	if err != nil {
		return nil, err
	}

	privilegedDiscoveryEligible := validatePrivilegedNmap(path, os.Geteuid(), runtime.GOOS, osPathSecurity) == nil
	return &Scanner{
		BinaryPath:                  path,
		credential:                  credential,
		privilegedDiscoveryEligible: privilegedDiscoveryEligible,
		localNetworks:               attachedNetworks,
		neighborSnapshot:            platformNeighborSnapshot(runtime.GOOS),
		timeout:                     defaultScanTimeout,
		maxStdout:                   defaultMaxNmapStdout,
		maxStderr:                   defaultMaxNmapStderr,
	}, nil
}

// Scan retains the original API for callers that do not have a lifecycle
// context. Long-running service callers should use ScanContext so shutdown can
// cancel nmap immediately.
func (s *Scanner) Scan(cidr string, withPorts bool) (*ScanResult, error) {
	return s.ScanContext(context.Background(), cidr, withPorts)
}

// ScanContext discovers hosts first, then (when requested) runs unprivileged
// TCP-connect probes only against the discovered IPs. Root is used solely for
// a fixed, no-DNS/no-port ARP discovery command, and only when the exact system
// nmap executable and the requested directly-attached IPv4 target pass all
// trust checks.
func (s *Scanner) ScanContext(ctx context.Context, cidr string, withPorts bool) (*ScanResult, error) {
	if ctx == nil {
		return nil, errors.New("scan context is nil")
	}
	// Re-validate the target here: it originates from Core work items and has
	// crossed a trust boundary. The literal "--" below stops nmap from
	// interpreting the target as an option, but "--" alone does not defend
	// against a metacharacter payload, so validation is mandatory.
	if err := ValidateTarget(cidr); err != nil {
		return nil, fmt.Errorf("refusing to scan invalid target: %w", err)
	}
	if !supportedNmapIPv4Target(cidr) {
		return nil, fmt.Errorf("active discovery is IPv4-only for this beta; hostnames and IPv6 targets are unsupported: %q", cidr)
	}

	start := time.Now()
	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultScanTimeout
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	privileged := s.shouldUsePrivilegedDiscovery(cidr)
	var before map[string]string
	var beforeOK bool
	if !privileged && s.neighborSnapshot != nil {
		before, beforeOK = snapshotNeighbors(scanCtx, s.neighborSnapshot)
	}

	discovery, complete, err := s.runNmap(scanCtx, discoveryArgs(cidr, privileged), privileged)
	if err != nil {
		if ctxErr := scanCtx.Err(); ctxErr != nil {
			return nil, scanContextError(ctx, ctxErr, timeout)
		}
		return nil, fmt.Errorf("nmap discovery failed: %w", err)
	}
	discoverySource := "active_nmap_connect"
	if privileged {
		discoverySource = "active_nmap_arp"
	}
	for i := range discovery.Hosts {
		if discovery.Hosts[i].DiscoverySource == "active_nmap" {
			discovery.Hosts[i].DiscoverySource = discoverySource
		}
	}
	if !privileged && complete && beforeOK && s.neighborSnapshot != nil {
		if after, ok := snapshotNeighbors(scanCtx, s.neighborSnapshot); ok {
			mergeNeighborDelta(discovery, before, after, cidr)
		}
	}

	if withPorts {
		hosts := discoveredIPs(discovery.Hosts)
		for offset := 0; offset < len(hosts); offset += portScanBatchSize {
			end := offset + portScanBatchSize
			if end > len(hosts) {
				end = len(hosts)
			}
			ports, _, err := s.runNmap(scanCtx, portScanArgs(hosts[offset:end]), false)
			if err != nil {
				if ctxErr := scanCtx.Err(); ctxErr != nil {
					return nil, scanContextError(ctx, ctxErr, timeout)
				}
				return nil, fmt.Errorf("nmap port scan failed: %w", err)
			}
			mergePortResults(discovery, ports)
		}
	}
	if err := scanCtx.Err(); err != nil {
		return nil, scanContextError(ctx, err, timeout)
	}
	discovery.ScanTime = start
	discovery.Duration = time.Since(start)
	return discovery, nil
}

func supportedNmapIPv4Target(target string) bool {
	if ip := net.ParseIP(target); ip != nil {
		return ip.To4() != nil && !strings.Contains(target, ":")
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		return network.IP.To4() != nil && !strings.Contains(target, ":")
	}
	// Preserve numeric ranges/lists while failing closed if this helper is ever
	// called independently of ValidateTarget.
	return nmapRangeRe.MatchString(target) && nmapRangeBreadth(target) <= maxScanAddresses
}

// Check executes the exact canonical runner with a short, network-free
// version query under the same unprivileged credentials and scrubbed
// environment used by scans. Merely finding a path is not a useful installer
// health check: the service account must be able to execute it successfully.
func (s *Scanner) Check(ctx context.Context) error {
	if ctx == nil {
		return errors.New("self-check context is nil")
	}
	checkCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	_, _, err := s.runCommand(checkCtx, []string{"--version"}, false, 64<<10, 64<<10)
	if err != nil {
		return fmt.Errorf("nmap self-check failed: %w", err)
	}
	return nil
}

// SelfCheck is retained as a descriptive compatibility alias for internal
// callers; new service code uses Check.
func (s *Scanner) SelfCheck(ctx context.Context) error { return s.Check(ctx) }

func discoveryArgs(target string, privileged bool) []string {
	if privileged {
		// Closed argument set: local ARP discovery only. No DNS, NSE, service
		// detection, scripts, or port probes are possible in this root child.
		return []string{"--privileged", "-sn", "-n", "-PR", "-oX", "-", "--", target}
	}
	// Disable reverse DNS here as well: discovery should touch only the requested
	// segment, not disclose every scanned address to the configured resolver.
	return []string{"--unprivileged", "-sn", "-n", "-oX", "-", "--", target}
}

func portScanArgs(hosts []string) []string {
	args := []string{"--unprivileged", "-Pn", "-n", "-sT", "--top-ports", "100", "-T4", "-oX", "-", "--"}
	return append(args, hosts...)
}

// command constructs the normal unprivileged direct exec. It remains as a
// small wrapper because tests and every non-discovery path must exercise this
// exact credential boundary.
func (s *Scanner) command(ctx context.Context, args []string) (*exec.Cmd, error) {
	return s.commandMode(ctx, args, false)
}

// commandMode validates the stored canonical executable immediately before
// direct exec. A root child is permitted only for the narrowly-gated discovery
// path; all other children drop to nobody/_nobody and clear supplementary
// groups. The child receives no token, proxy, or dynamic-loader variables.
func (s *Scanner) commandMode(ctx context.Context, args []string, privileged bool) (*exec.Cmd, error) {
	path, err := canonicalExecutable(s.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("validate nmap before execution: %w", err)
	}
	if path != s.BinaryPath {
		return nil, fmt.Errorf("refusing changed nmap canonical path: configured %q now resolves to %q", s.BinaryPath, path)
	}
	if privileged {
		if err := validatePrivilegedNmap(path, os.Geteuid(), runtime.GOOS, osPathSecurity); err != nil {
			return nil, fmt.Errorf("refusing privileged nmap discovery: %w", err)
		}
	}

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string(nil), minimalNmapEnvironment...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !privileged && os.Geteuid() == 0 && (s.credential == nil || s.credential.Uid == 0 || s.credential.Gid == 0) {
		return nil, fmt.Errorf("refusing to execute nmap from a root sensor without a valid unprivileged credential")
	}
	if !privileged && s.credential != nil {
		credential := *s.credential
		// A non-nil empty slice makes os/exec call setgroups(0, nil), rather
		// than inheriting the root parent's supplementary groups.
		credential.Groups = make([]uint32, 0)
		credential.NoSetGroups = false
		cmd.SysProcAttr.Credential = &credential
	}
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = childWaitDelay
	return cmd, nil
}

func (s *Scanner) runNmap(ctx context.Context, args []string, privileged bool) (*ScanResult, bool, error) {
	stdout, stderr, err := s.runCommand(ctx, args, privileged, s.maxStdout, s.maxStderr)
	if err != nil {
		if detail := strings.TrimSpace(string(stderr)); detail != "" {
			return nil, false, fmt.Errorf("%w: %s", err, detail)
		}
		return nil, false, err
	}
	result, complete, err := parseNmapXMLDetailed(stdout, time.Now(), 0)
	return result, complete, err
}

func (s *Scanner) runCommand(ctx context.Context, args []string, privileged bool, stdoutLimit, stderrLimit int64) ([]byte, []byte, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, err := s.commandMode(runCtx, args, privileged)
	if err != nil {
		return nil, nil, err
	}
	stdout := newBoundedBuffer(stdoutLimit, defaultMaxNmapStdout, cancel)
	stderr := newBoundedBuffer(stderrLimit, defaultMaxNmapStderr, cancel)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Run()
	if stdout.Truncated() {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("nmap stdout exceeded %d-byte limit; refusing partial results", stdout.Limit())
	}
	if stderr.Truncated() {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("nmap stderr exceeded %d-byte limit", stderr.Limit())
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return stdout.Bytes(), stderr.Bytes(), ctxErr
	}
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("nmap exited unsuccessfully: %w", err)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func scanContextError(caller context.Context, err error, timeout time.Duration) error {
	if callerErr := caller.Err(); callerErr != nil {
		return fmt.Errorf("nmap scan canceled by caller: %w", callerErr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("nmap scan timed out after %s: %w", timeout, err)
	}
	return fmt.Errorf("nmap scan canceled: %w", err)
}

func (s *Scanner) shouldUsePrivilegedDiscovery(target string) bool {
	if !s.privilegedDiscoveryEligible || s.localNetworks == nil {
		return false
	}
	networks, err := s.localNetworks()
	return err == nil && targetLocallyAttachedIPv4(target, networks)
}

type pathSecurity struct {
	mode os.FileMode
	uid  uint32
}

type pathSecurityFunc func(string) (pathSecurity, error)

func osPathSecurity(path string) (pathSecurity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return pathSecurity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pathSecurity{}, fmt.Errorf("unsupported file ownership metadata for %s", path)
	}
	return pathSecurity{mode: info.Mode(), uid: stat.Uid}, nil
}

func canonicalExecutable(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("nmap path is not absolute: %q", path)
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("nmap is not a regular file: %q", canonical)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return "", fmt.Errorf("nmap may not be setuid/setgid: %q", canonical)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("nmap is not executable: %q", canonical)
	}
	if err := rejectExecutableCapabilities(canonical, executableHasCapabilities); err != nil {
		return "", err
	}
	return filepath.Clean(canonical), nil
}

type executableCapabilityCheck func(string) (bool, error)

func rejectExecutableCapabilities(path string, check executableCapabilityCheck) error {
	hasCapabilities, err := check(path)
	if err != nil {
		return fmt.Errorf("inspect nmap file capabilities: %w", err)
	}
	if hasCapabilities {
		return fmt.Errorf("nmap may not carry file capabilities: %q", path)
	}
	return nil
}

// validatePrivilegedNmap is deliberately much stricter than ordinary runner
// validation. Only a root Linux parent may retain privilege, and only for an
// immutable-looking canonical system binary whose entire ancestry is root-owned
// and not group/world-writable.
func validatePrivilegedNmap(path string, euid int, goos string, stat pathSecurityFunc) error {
	if goos != "linux" {
		return errors.New("privileged discovery is Linux-only")
	}
	if euid != 0 {
		return errors.New("privileged discovery requires a root parent")
	}
	path = filepath.Clean(path)
	if path != "/usr/bin/nmap" && path != "/usr/sbin/nmap" {
		return fmt.Errorf("canonical nmap path %q is not an approved system path", path)
	}
	parts := []string{"/", "/usr", filepath.Dir(path), path}
	seen := make(map[string]struct{}, len(parts))
	for i, part := range parts {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		security, err := stat(part)
		if err != nil {
			return fmt.Errorf("stat %s: %w", part, err)
		}
		if security.uid != 0 {
			return fmt.Errorf("%s is not root-owned", part)
		}
		if security.mode.Perm()&0o022 != 0 {
			return fmt.Errorf("%s is group/world-writable", part)
		}
		if i == len(parts)-1 {
			if !security.mode.IsRegular() || security.mode.Perm()&0o111 == 0 || security.mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return fmt.Errorf("%s is not a regular executable", part)
			}
		} else if !security.mode.IsDir() {
			return fmt.Errorf("%s is not a directory", part)
		}
	}
	return nil
}

func attachedNetworks() ([]net.IPNet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var networks []net.IPNet
	for _, iface := range interfaces {
		if !arpCapableInterface(iface.Flags) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			_, network, err := net.ParseCIDR(addr.String())
			if err == nil {
				networks = append(networks, *network)
			}
		}
	}
	return networks, nil
}

func arpCapableInterface(flags net.Flags) bool {
	return flags&net.FlagUp != 0 &&
		flags&net.FlagLoopback == 0 &&
		flags&net.FlagPointToPoint == 0 &&
		flags&net.FlagBroadcast != 0
}

func targetLocallyAttachedIPv4(target string, networks []net.IPNet) bool {
	if ip := net.ParseIP(target); ip != nil {
		ip = ip.To4()
		if ip == nil {
			return false
		}
		for _, local := range networks {
			if local.IP.To4() != nil && local.Contains(ip) {
				return true
			}
		}
		return false
	}
	_, requested, err := net.ParseCIDR(target)
	if err != nil || requested.IP.To4() == nil {
		return false
	}
	requestedOnes, requestedBits := requested.Mask.Size()
	for _, local := range networks {
		localOnes, localBits := local.Mask.Size()
		if local.IP.To4() == nil || localBits != requestedBits || requestedOnes < localOnes {
			continue
		}
		if local.Contains(requested.IP.Mask(requested.Mask)) {
			return true
		}
	}
	return false
}

func discoveredIPs(hosts []DiscoveredHost) []string {
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if ip := net.ParseIP(host.IPAddress); ip != nil {
			seen[ip.String()] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for ip := range seen {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result
}

func mergePortResults(discovery, ports *ScanResult) {
	if discovery == nil || ports == nil {
		return
	}
	byIP := make(map[string]*DiscoveredHost, len(discovery.Hosts))
	for i := range discovery.Hosts {
		byIP[discovery.Hosts[i].IPAddress] = &discovery.Hosts[i]
	}
	for _, probed := range ports.Hosts {
		host := byIP[probed.IPAddress]
		if host == nil {
			continue // never expand a finding beyond the discovery allowlist
		}
		set := make(map[int]struct{}, len(host.OpenPorts)+len(probed.OpenPorts))
		for _, port := range host.OpenPorts {
			if port > 0 && port <= 65535 {
				set[port] = struct{}{}
			}
		}
		for _, port := range probed.OpenPorts {
			if port > 0 && port <= 65535 {
				set[port] = struct{}{}
			}
		}
		host.OpenPorts = host.OpenPorts[:0]
		for port := range set {
			host.OpenPorts = append(host.OpenPorts, port)
		}
		sort.Ints(host.OpenPorts)
	}
}

func snapshotNeighbors(ctx context.Context, snapshot func(context.Context) (map[string]string, error)) (map[string]string, bool) {
	neighbors, err := snapshot(ctx)
	if err != nil || ctx.Err() != nil {
		return nil, false
	}
	return neighbors, true
}

// mergeNeighborDelta accepts only complete-cache entries that appeared or
// changed during a successful discovery run. Pre-existing entries are ignored
// because ARP/neighbor tables do not provide a portable freshness timestamp.
func mergeNeighborDelta(result *ScanResult, before, after map[string]string, target string) {
	if result == nil {
		return
	}
	byIP := make(map[string]int, len(result.Hosts))
	for i := range result.Hosts {
		byIP[result.Hosts[i].IPAddress] = i
	}
	keys := make([]string, 0, len(after))
	for ip := range after {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	for _, ip := range keys {
		mac, ok := normalizeNeighbor(ip, after[ip])
		if !ok || !targetContainsIP(target, ip) {
			continue
		}
		if previous, existed := before[ip]; existed {
			if oldMAC, valid := normalizeNeighbor(ip, previous); valid && oldMAC == mac {
				// An unchanged cache row cannot independently prove a quiet host is
				// current, but it can safely enrich an IP Nmap just confirmed live.
				if index, found := byIP[ip]; found && result.Hosts[index].MACAddress == "" {
					result.Hosts[index].MACAddress = mac
					result.Hosts[index].DiscoverySource += "+neighbor_cache_confirmed"
				}
				continue
			}
		}
		if index, found := byIP[ip]; found {
			if result.Hosts[index].MACAddress == "" {
				result.Hosts[index].MACAddress = mac
				if result.Hosts[index].DiscoverySource == "" {
					result.Hosts[index].DiscoverySource = "neighbor_cache_delta"
				} else if !strings.Contains(result.Hosts[index].DiscoverySource, "neighbor_cache_delta") {
					result.Hosts[index].DiscoverySource += "+neighbor_cache_delta"
				}
			}
			continue
		}
		byIP[ip] = len(result.Hosts)
		result.Hosts = append(result.Hosts, DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "up", DiscoverySource: "neighbor_cache_delta",
		})
	}
}

func normalizeNeighbor(ip, rawMAC string) (string, bool) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", false
	}
	hardware, err := net.ParseMAC(rawMAC)
	if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 {
		return "", false
	}
	allZero := true
	for _, b := range hardware {
		if b != 0 {
			allZero = false
			break
		}
	}
	mac := strings.ToLower(hardware.String())
	if allZero || !isRealNeighbor(parsedIP.String(), mac) {
		return "", false
	}
	return mac, true
}

func targetContainsIP(target, candidate string) bool {
	return targetContainsIPv4(target, candidate)
}

func platformNeighborSnapshot(goos string) func(context.Context) (map[string]string, error) {
	switch goos {
	case "linux":
		return readLinuxNeighbors
	case "darwin":
		return readDarwinNeighbors
	default:
		return nil
	}
}

func readLinuxNeighbors(ctx context.Context) (map[string]string, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseLinuxNeighbors(ctx, file)
}

func parseLinuxNeighbors(ctx context.Context, input io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(input)
	if scanner.Scan() { // header
		// Intentionally discarded.
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		flags, err := strconv.ParseUint(fields[2], 0, 32)
		if err != nil || flags&0x2 == 0 { // ATF_COM: complete/resolved only
			continue
		}
		if mac, ok := normalizeNeighbor(fields[0], fields[3]); ok {
			result[fields[0]] = mac
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

var darwinARPLine = regexp.MustCompile(`\(([0-9]+(?:\.[0-9]+){3})\)\s+at\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+on\s+\S+`)

func readDarwinNeighbors(ctx context.Context) (map[string]string, error) {
	const arpPath = "/usr/sbin/arp"
	path, err := canonicalExecutable(arpPath)
	if err != nil || path != arpPath {
		return nil, fmt.Errorf("trusted arp reader unavailable")
	}
	if err := validateTrustedRootPath(path, osPathSecurity); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, path, "-an")
	cmd.Env = append([]string(nil), minimalNmapEnvironment...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = childWaitDelay
	stdout := newBoundedBuffer(1<<20, 1<<20, cancel)
	cmd.Stdout = stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if stdout.Truncated() {
		return nil, errors.New("arp neighbor snapshot exceeded 1 MiB")
	}
	result := make(map[string]string)
	for _, match := range darwinARPLine.FindAllSubmatch(stdout.Bytes(), -1) {
		ip, rawMAC := string(match[1]), string(match[2])
		if mac, ok := normalizeNeighbor(ip, rawMAC); ok {
			result[ip] = mac
		}
	}
	return result, nil
}

func validateTrustedRootPath(path string, stat pathSecurityFunc) error {
	parts := []string{"/"}
	for current := filepath.Dir(path); current != "/" && current != "."; current = filepath.Dir(current) {
		parts = append(parts, current)
	}
	parts = append(parts, path)
	for i, part := range parts {
		security, err := stat(part)
		if err != nil {
			return err
		}
		if security.uid != 0 || security.mode.Perm()&0o022 != 0 {
			return fmt.Errorf("untrusted root path component %s", part)
		}
		if i == len(parts)-1 {
			if !security.mode.IsRegular() || security.mode.Perm()&0o111 == 0 {
				return fmt.Errorf("trusted reader %s is not a regular executable", part)
			}
		} else if !security.mode.IsDir() {
			return fmt.Errorf("trusted reader ancestor %s is not a directory", part)
		}
	}
	return nil
}

type lookupUserFunc func(string) (*user.User, error)

// nmapCredential returns nil for a non-root parent. A root parent fails closed
// unless it can resolve a non-root nobody account. Both common Unix spellings
// are supported because macOS releases and Linux distributions differ.
func nmapCredential(euid int, goos string, lookup lookupUserFunc) (*syscall.Credential, error) {
	if euid != 0 {
		return nil, nil
	}

	names := []string{"nobody", "_nobody"}
	if goos == "darwin" {
		names = []string{"_nobody", "nobody"}
	}
	var lastErr error
	for _, name := range names {
		account, err := lookup(name)
		if err != nil {
			lastErr = err
			continue
		}
		uid, err := parseCredentialID(account.Uid)
		if err != nil {
			lastErr = fmt.Errorf("parse %s uid: %w", name, err)
			continue
		}
		gid, err := parseCredentialID(account.Gid)
		if err != nil {
			lastErr = fmt.Errorf("parse %s gid: %w", name, err)
			continue
		}
		if uid == 0 || gid == 0 {
			lastErr = fmt.Errorf("%s unexpectedly resolves to privileged uid/gid %d:%d", name, uid, gid)
			continue
		}
		return &syscall.Credential{
			Uid:         uid,
			Gid:         gid,
			Groups:      make([]uint32, 0),
			NoSetGroups: false,
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("account lookup returned no usable identity")
	}
	return nil, fmt.Errorf("cannot resolve an unprivileged nobody/_nobody account for nmap: %w", lastErr)
}

// macOS may represent nobody as the signed uid -2 while Go's os/user can expose
// the same credential as uint32(2^32-2). Accept both encodings.
func parseCredentialID(raw string) (uint32, error) {
	if value, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return uint32(value), nil
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid credential id %q", raw)
	}
	return uint32(int32(value)), nil
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
		return nil
	} else if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	// Setpgid should make the group kill reliable. Retain a direct-process
	// fallback so a platform-specific failure still terminates nmap itself.
	return cmd.Process.Kill()
}

// boundedBuffer retains at most limit bytes while continuing to consume the
// child's pipe. Returning the full input length prevents a noisy child from
// blocking forever after the memory cap is reached.
type boundedBuffer struct {
	buffer      bytes.Buffer
	limit       int64
	truncated   bool
	onTruncated func()
}

func newBoundedBuffer(limit, fallback int64, onTruncated func()) *boundedBuffer {
	if limit <= 0 {
		limit = fallback
	}
	return &boundedBuffer{limit: limit, onTruncated: onTruncated}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := b.limit - int64(b.buffer.Len())
	if remaining > 0 {
		keep := int64(len(data))
		if keep > remaining {
			keep = remaining
		}
		_, _ = b.buffer.Write(data[:keep])
	}
	if int64(len(data)) > remaining {
		if !b.truncated {
			b.truncated = true
			if b.onTruncated != nil {
				b.onTruncated()
			}
		}
	}
	return written, nil
}

func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }
func (b *boundedBuffer) Limit() int64   { return b.limit }
func (b *boundedBuffer) Truncated() bool {
	return b.truncated
}

// --- nmap XML parsing ---

type nmapRun struct {
	XMLName  xml.Name     `xml:"nmaprun"`
	Hosts    []nmapHost   `xml:"host"`
	Targets  []nmapTarget `xml:"target"`
	RunStats nmapRunStats `xml:"runstats"`
}

type nmapTarget struct {
	Status string `xml:"status,attr"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapRunStats struct {
	Finished nmapFinished `xml:"finished"`
}

type nmapFinished struct {
	Elapsed string `xml:"elapsed,attr"`
	Exit    string `xml:"exit,attr"`
}

func parseNmapXML(data []byte, scanTime time.Time, duration time.Duration) (*ScanResult, error) {
	result, _, err := parseNmapXMLDetailed(data, scanTime, duration)
	return result, err
}

func parseNmapXMLDetailed(data []byte, scanTime time.Time, duration time.Duration) (*ScanResult, bool, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, false, fmt.Errorf("failed to parse nmap XML: %w", err)
	}
	if run.XMLName.Local != "nmaprun" {
		return nil, false, errors.New("failed to parse nmap XML: unexpected root element")
	}
	for _, target := range run.Targets {
		if strings.EqualFold(target.Status, "skipped") {
			return nil, false, errors.New("nmap skipped the requested scan target")
		}
	}

	result := &ScanResult{
		ScanTime: scanTime,
		Duration: duration,
	}

	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}

		host := DiscoveredHost{Status: h.Status.State, DiscoverySource: "active_nmap"}

		for _, addr := range h.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if ip := net.ParseIP(addr.Addr); ip != nil {
					host.IPAddress = ip.String()
				}
			case "mac":
				host.MACAddress = strings.ToUpper(addr.Addr)
				if addr.Vendor != "" {
					host.Vendor = addr.Vendor
				}
			}
		}

		for _, hn := range h.Hostnames {
			if hn.Name != "" {
				host.Hostname = hn.Name
				break
			}
		}

		for _, p := range h.Ports {
			if p.State.State == "open" {
				host.OpenPorts = append(host.OpenPorts, p.PortID)
			}
		}

		if host.IPAddress != "" {
			result.Hosts = append(result.Hosts, host)
		}
	}

	if run.RunStats.Finished.Elapsed != "" {
		if secs, err := strconv.ParseFloat(run.RunStats.Finished.Elapsed, 64); err == nil {
			result.Duration = time.Duration(secs * float64(time.Second))
		}
	}

	return result, strings.EqualFold(run.RunStats.Finished.Exit, "success"), nil
}
