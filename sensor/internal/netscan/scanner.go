package netscan

import (
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// hostnameRe matches a strict DNS hostname: one or more labels separated by
// dots, each label 1-63 chars of [A-Za-z0-9-] not starting/ending with a
// hyphen. A trailing dot is not permitted.
var hostnameRe = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// nmapRangeRe matches an nmap numeric octet-range target such as
// 10.0.0.1-50 or 192.168.1-10.0-255. Each of the four octets is either a
// single number or a low-high range.
var nmapRangeRe = regexp.MustCompile(`^(?:\d{1,3}(?:-\d{1,3})?)(?:\.\d{1,3}(?:-\d{1,3})?){3}$`)

// shellMeta holds characters that must never appear in a scan target. Their
// presence indicates an attempt at shell or nmap-option injection.
const shellMeta = ";|&$`<>()'\"\\"

// ValidateTarget re-validates a scan target that crossed the trust boundary
// from Core before it is handed to nmap. The sensor runs as root, so an
// attacker-controlled target that reached an nmap argument could inject
// options (e.g. --script=...) or, via a shell metacharacter, arbitrary
// commands. These rules are intentionally duplicated from the backend: the
// sensor is a separate Go module and cannot import it.
//
// A target is valid ONLY if it is one of:
//   - a bare IP (net.ParseIP)
//   - a CIDR block (net.ParseCIDR)
//   - an nmap numeric octet range like 10.0.0.1-50
//   - a strict DNS hostname
//
// Any value that begins with "-", contains whitespace, or contains a shell/
// option metacharacter is rejected regardless of the above.
func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("empty scan target")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("scan target may not begin with '-': %q", target)
	}
	if strings.ContainsAny(target, " \t\r\n\f\v") {
		return fmt.Errorf("scan target may not contain whitespace: %q", target)
	}
	if strings.ContainsAny(target, shellMeta) {
		return fmt.Errorf("scan target contains forbidden metacharacter: %q", target)
	}

	if net.ParseIP(target) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}
	if nmapRangeRe.MatchString(target) {
		return nil
	}
	if hostnameRe.MatchString(target) {
		return nil
	}

	return fmt.Errorf("scan target is not a valid IP, CIDR, range, or hostname: %q", target)
}

// ScanResult represents the parsed output of an nmap scan.
type ScanResult struct {
	Hosts    []DiscoveredHost `json:"hosts"`
	ScanTime time.Time        `json:"scan_time"`
	Duration time.Duration    `json:"duration"`
}

// DiscoveredHost represents a single host found by nmap (or passive discovery).
type DiscoveredHost struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	OpenPorts  []int  `json:"open_ports,omitempty"`
	Status     string `json:"status"` // up | down

	// Actionability fields from passive discovery (mDNS/DHCP/SSDP etc).
	Model           string   `json:"model,omitempty"`
	FriendlyName    string   `json:"friendly_name,omitempty"` // human-readable label derived from mDNS instance / TXT fn=/n= / SSDP (spec 004)
	Services        []string `json:"services,omitempty"`
	DiscoverySource string   `json:"discovery_source,omitempty"`
}

// Scanner wraps nmap execution.
type Scanner struct {
	BinaryPath string
}

// NewScanner creates a Scanner, verifying nmap is available.
func NewScanner() (*Scanner, error) {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return nil, fmt.Errorf("nmap not found in PATH: %w", err)
	}
	return &Scanner{BinaryPath: path}, nil
}

// Scan runs nmap against the given CIDR and returns parsed results.
// Uses -sn (ping scan) for host discovery.
// If withPorts is true, uses -sS with top-100 ports instead.
func (s *Scanner) Scan(cidr string, withPorts bool) (*ScanResult, error) {
	// Re-validate the target here: it originates from Core work items and has
	// crossed a trust boundary. The literal "--" below stops nmap from
	// interpreting the target as an option, but "--" alone does not defend
	// against a metacharacter payload, so validation is mandatory.
	if err := ValidateTarget(cidr); err != nil {
		return nil, fmt.Errorf("refusing to scan invalid target: %w", err)
	}

	// The "--" terminator immediately precedes the target operand so nmap
	// treats it as a positional argument even if it began with '-'.
	args := []string{"-sn", "-oX", "-", "--", cidr}
	if withPorts {
		args = []string{"-sS", "--top-ports", "100", "-T4", "-oX", "-", "--", cidr}
	}

	start := time.Now()
	cmd := exec.Command(s.BinaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap scan failed: %w", err)
	}
	duration := time.Since(start)

	return parseNmapXML(output, start, duration)
}

// --- nmap XML parsing ---

type nmapRun struct {
	XMLName  xml.Name     `xml:"nmaprun"`
	Hosts    []nmapHost   `xml:"host"`
	RunStats nmapRunStats `xml:"runstats"`
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
}

func parseNmapXML(data []byte, scanTime time.Time, duration time.Duration) (*ScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
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
				host.IPAddress = addr.Addr
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

	return result, nil
}
