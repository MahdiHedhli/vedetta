//go:build !windows

package iotsecurity

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
)

// Capturer consumes a narrow passive UDP stream. It never transmits a packet.
// Its callback should return promptly, normally by enqueueing into a bounded
// delivery queue. Start and Stop can be used again after a previous run ends.
type Capturer struct {
	mu       sync.Mutex
	iface    string
	config   Config
	networks []*net.IPNet
	localIP  string
	running  bool
	stopping bool
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func NewCapturer(cfg Config) (*Capturer, error) {
	cidr := strings.TrimSpace(cfg.CIDR)
	if ip := net.ParseIP(cidr); ip != nil {
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		cidr = fmt.Sprintf("%s/%d", ip.String(), bits)
	}
	iface := strings.TrimSpace(cfg.Interface)
	if iface == "" || iface == "auto" {
		selection, err := netinfo.SelectCaptureInterface(netinfo.CaptureSelectionOptions{
			Preferred: cfg.Interface, CoreURL: cfg.CoreURL, ScanCIDR: cidr, Purpose: "IoT security observation",
		})
		if err != nil {
			return nil, fmt.Errorf("select IoT observation interface: %w", err)
		}
		iface = selection.Name
		log.Printf("iotsecurity: %s", netinfo.FormatCaptureSelection(selection, "IoT security observation"))
	}
	c := &Capturer{iface: iface, config: cfg}
	if cidr != "" && cidr != "auto" {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("IoT observation scope must be a valid CIDR or literal IP: %w", err)
		}
		c.networks = append(c.networks, subnet)
	}
	// Without an explicit CIDR, local interface networks provide a conservative
	// subject scope. Public STUN peers are never reported as the local subject.
	if networkInterface, err := net.InterfaceByName(iface); err == nil {
		addresses, err := networkInterface.Addrs()
		if err == nil {
			for _, address := range addresses {
				ip, subnet, err := net.ParseCIDR(address.String())
				if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
					continue
				}
				if cidr == "" || cidr == "auto" {
					c.networks = append(c.networks, subnet)
				}
				if c.localIP == "" && c.subjectAllowed(ip.String()) {
					c.localIP = ip.String()
				}
			}
		}
	}
	if len(c.networks) == 0 {
		return nil, fmt.Errorf("IoT capture requires an explicit CIDR or an interface with local address networks")
	}
	return c, nil
}

func (c *Capturer) Interface() string { return c.iface }

func (c *Capturer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("IoT observation capture is already running")
	}
	handle, err := pcap.OpenLive(c.iface, 65535, c.config.Promiscuous, 250*time.Millisecond)
	if err != nil {
		return fmt.Errorf("open IoT observation capture: %w", err)
	}
	if err := handle.SetBPFFilter(CaptureFilter); err != nil {
		handle.Close()
		return fmt.Errorf("set IoT observation capture filter: %w", err)
	}
	c.stopCh, c.doneCh = make(chan struct{}), make(chan struct{})
	c.running, c.stopping = true, false
	go c.loop(handle, c.stopCh, c.doneCh)
	log.Printf("iotsecurity: passive UDP observation started on %s with filter %q", c.iface, CaptureFilter)
	return nil
}

// Stop is safe before Start, after an error, and from concurrent shutdown paths.
func (c *Capturer) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	if !c.stopping {
		close(c.stopCh)
		c.stopping = true
	}
	done := c.doneCh
	c.mu.Unlock()
	<-done
}

func (c *Capturer) loop(handle *pcap.Handle, stop <-chan struct{}, done chan struct{}) {
	defer func() {
		handle.Close()
		c.mu.Lock()
		c.running, c.stopping = false, false
		close(done)
		c.mu.Unlock()
	}()
	detector := NewPacketDetector()
	for {
		select {
		case <-stop:
			return
		default:
		}
		data, info, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("iotsecurity: passive capture stopped after read failure: %v", err)
			}
			if c.localIP != "" && c.config.OnObservation != nil {
				coverage := newObservation(time.Now(), c.localIP, "coverage", nil)
				coverage.Coverage = []Coverage{{Check: "passive_iot_capture", Status: "unavailable", Detail: "capture input ended; network evidence is no longer being observed"}}
				c.config.OnObservation(coverage)
			}
			return
		}
		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = info
		// Filter before allocating detector state as well as before delivery.
		// For Realtek requests the victim is the destination; STUN evidence
		// belongs to its source, independently of a peer's reputation.
		facts, _, ok := packetEvidence(packet)
		if !ok {
			continue
		}
		subject := facts.SourceIP
		if facts.DestinationPort == 9034 {
			subject = facts.DestinationIP
		}
		if !c.subjectAllowed(subject) {
			continue
		}
		for _, observation := range detector.ObservePacket(packet) {
			if c.config.OnObservation != nil {
				c.config.OnObservation(observation)
			}
		}
	}
}

func (c *Capturer) subjectAllowed(subject string) bool {
	ip := net.ParseIP(subject)
	if ip == nil {
		return false
	}
	for _, network := range c.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
