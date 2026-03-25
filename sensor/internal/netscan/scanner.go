package netscan

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ScanResult represents the parsed output of an nmap scan.
type ScanResult struct {
	Hosts    []DiscoveredHost `json:"hosts"`
	ScanTime time.Time        `json:"scan_time"`
	Duration time.Duration    `json:"duration"`
}

// DiscoveredHost represents a single host found by nmap.
type DiscoveredHost struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	OpenPorts  []int  `json:"open_ports,omitempty"`
	Status     string `json:"status"` // up | down
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

		host := DiscoveredHost{Status: h.Status.State}

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
