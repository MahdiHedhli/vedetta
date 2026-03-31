package dnsingest

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

// IPTablesSource manages iptables-based DNS interception (Linux only).
type IPTablesSource struct {
	resolverPort int
	localIP      string
	mu           sync.Mutex
	installed    bool
	name         string
}

// NewIPTablesSource creates a new iptables-based DNS source.
// Only functional on Linux; will log warnings on other platforms.
func NewIPTablesSource(resolverPort int, localIP string) *IPTablesSource {
	if runtime.GOOS != "linux" {
		log.Printf("WARNING: iptables DNS interception is Linux-only; running on %s", runtime.GOOS)
	}
	return &IPTablesSource{
		resolverPort: resolverPort,
		localIP:      localIP,
		installed:    false,
		name:         "iptables_intercept",
	}
}

// Name returns the source identifier.
func (i *IPTablesSource) Name() string {
	return i.name
}

// Start installs iptables rules to redirect port 53 to the resolver.
func (i *IPTablesSource) Start() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.installed {
		return nil
	}

	if runtime.GOOS != "linux" {
		log.Printf("iptables_intercept: skipping on non-Linux platform (%s)", runtime.GOOS)
		return nil
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Printf("WARNING: iptables rules require root; running as UID %d", os.Geteuid())
		return fmt.Errorf("iptables: requires root privileges")
	}

	// Install DNAT rule for UDP port 53
	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "udp", "-d", "0.0.0.0/0", "--dport", "53",
		"-j", "DNAT", "--to", fmt.Sprintf("%s:%d", i.localIP, i.resolverPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install UDP rule: %w", err)
	}

	// Install DNAT rule for TCP port 53
	cmd = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "tcp", "-d", "0.0.0.0/0", "--dport", "53",
		"-j", "DNAT", "--to", fmt.Sprintf("%s:%d", i.localIP, i.resolverPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install TCP rule: %w", err)
	}

	// Install MASQUERADE rule for responses
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-p", "udp", "-d", i.localIP, "--dport", fmt.Sprintf("%d", i.resolverPort),
		"-j", "MASQUERADE")
	cmd.Run() // non-fatal if fails

	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-p", "tcp", "-d", i.localIP, "--dport", fmt.Sprintf("%d", i.resolverPort),
		"-j", "MASQUERADE")
	cmd.Run() // non-fatal if fails

	i.installed = true
	log.Printf("iptables_intercept: rules installed on %s:%d", i.localIP, i.resolverPort)
	return nil
}

// Stop removes iptables rules and stops DNS interception.
func (i *IPTablesSource) Stop() {
	i.mu.Lock()
	defer i.mu.Unlock()

	if !i.installed {
		return
	}

	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return
	}

	// Remove DNAT rule for UDP port 53
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "udp", "-d", "0.0.0.0/0", "--dport", "53",
		"-j", "DNAT", "--to", fmt.Sprintf("%s:%d", i.localIP, i.resolverPort))
	cmd.Run()

	// Remove DNAT rule for TCP port 53
	cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "tcp", "-d", "0.0.0.0/0", "--dport", "53",
		"-j", "DNAT", "--to", fmt.Sprintf("%s:%d", i.localIP, i.resolverPort))
	cmd.Run()

	// Remove MASQUERADE rules
	cmd = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-p", "udp", "-d", i.localIP, "--dport", fmt.Sprintf("%d", i.resolverPort),
		"-j", "MASQUERADE")
	cmd.Run()

	cmd = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-p", "tcp", "-d", i.localIP, "--dport", fmt.Sprintf("%d", i.resolverPort),
		"-j", "MASQUERADE")
	cmd.Run()

	i.installed = false
	log.Printf("iptables_intercept: rules removed")
}
