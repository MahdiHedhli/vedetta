package discovery

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NmapResult represents the parsed output of an nmap scan.
type NmapResult struct {
	Hosts    []DiscoveredHost
	ScanTime time.Time
	Duration time.Duration
}

// DiscoveredHost represents a single host found by nmap.
type DiscoveredHost struct {
	IPAddress  string
	MACAddress string
	Hostname   string
	Vendor     string
	OpenPorts  []int
	Status     string // up | down
}

// nmapRun is the top-level XML element from nmap -oX output.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
	RunStats nmapRunStats `xml:"runstats"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // ipv4 | mac
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
}

type nmapPortState struct {
	State string `xml:"state,attr"` // open | closed | filtered
}

type nmapRunStats struct {
	Finished nmapFinished `xml:"finished"`
}

type nmapFinished struct {
	Elapsed string `xml:"elapsed,attr"`
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
// Uses -sn (ping scan) + -oX (XML output) for fast host discovery.
// If withPorts is true, adds a quick top-100 port scan.
func (s *Scanner) Scan(cidr string, withPorts bool) (*NmapResult, error) {
	args := []string{"-sn", "-oX", "-", cidr}
	if withPorts {
		args = []string{"-sS", "--top-ports", "100", "-T4", "-oX", "-", cidr}
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

// parseNmapXML parses nmap's XML output into our domain types.
func parseNmapXML(data []byte, scanTime time.Time, duration time.Duration) (*NmapResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	result := &NmapResult{
		ScanTime: scanTime,
		Duration: duration,
	}

	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}

		host := DiscoveredHost{
			Status: h.Status.State,
		}

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

		// Skip hosts with no IP (shouldn't happen, but defensive)
		if host.IPAddress != "" {
			result.Hosts = append(result.Hosts, host)
		}
	}

	// Parse elapsed time from nmap stats
	if run.RunStats.Finished.Elapsed != "" {
		if secs, err := strconv.ParseFloat(run.RunStats.Finished.Elapsed, 64); err == nil {
			result.Duration = time.Duration(secs * float64(time.Second))
		}
	}

	return result, nil
}
