package passive

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// Config controls passive device discovery.
type Config struct {
	Interface  string
	CoreURL    string
	CIDR       string
	EnableARP  bool
	EnableDHCP bool
	EnableMDNS bool
	EnableSSDP bool
	OnHost     func(netscan.DiscoveredHost)
}

// Capturer listens for passive discovery signals on the local network.
type Capturer struct {
	iface   string
	filter  string
	config  Config
	handler *pcap.Handle

	mu     sync.Mutex
	stopCh chan struct{}
	doneCh chan struct{}
	run    bool
}

// NewCapturer creates a passive discovery capturer.
func NewCapturer(cfg Config) (*Capturer, error) {
	if !cfg.EnableARP && !cfg.EnableDHCP && !cfg.EnableMDNS && !cfg.EnableSSDP {
		return nil, fmt.Errorf("no passive discovery sources enabled")
	}

	iface := strings.TrimSpace(cfg.Interface)
	if iface == "" || iface == "auto" {
		selection, err := netinfo.SelectCaptureInterface(netinfo.CaptureSelectionOptions{
			Preferred: cfg.Interface,
			CoreURL:   cfg.CoreURL,
			ScanCIDR:  cfg.CIDR,
			Purpose:   "passive discovery",
		})
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
		iface = selection.Name
		log.Printf("passive: %s", netinfo.FormatCaptureSelection(selection, "passive discovery"))
	}

	return &Capturer{
		iface:   iface,
		filter:  captureFilter(cfg),
		config:  cfg,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		handler: nil,
	}, nil
}

// Start begins passive capture in the background.
func (c *Capturer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.run {
		return fmt.Errorf("capturer already running")
	}

	handle, err := pcap.OpenLive(c.iface, 65535, false, 30*time.Second)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", c.iface, err)
	}
	if err := handle.SetBPFFilter(c.filter); err != nil {
		handle.Close()
		return fmt.Errorf("set BPF filter: %w", err)
	}

	c.handler = handle
	c.run = true
	go c.loop()
	log.Printf("passive: discovery capture started on interface %s with filter %q", c.iface, c.filter)
	return nil
}

// Interface returns the active capture interface.
func (c *Capturer) Interface() string {
	return c.iface
}

// Stop gracefully stops passive capture.
func (c *Capturer) Stop() {
	c.mu.Lock()
	if !c.run {
		c.mu.Unlock()
		return
	}
	close(c.stopCh)
	c.mu.Unlock()

	<-c.doneCh

	c.mu.Lock()
	if c.handler != nil {
		c.handler.Close()
		c.handler = nil
	}
	c.run = false
	c.mu.Unlock()

	log.Printf("passive: discovery capture stopped")
}

func (c *Capturer) loop() {
	defer close(c.doneCh)

	packetSource := gopacket.NewPacketSource(c.handler, c.handler.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			for _, host := range parsePacket(packet, c.config) {
				if c.config.OnHost != nil {
					c.config.OnHost(host)
				}
			}
		case <-c.stopCh:
			return
		}
	}
}

func captureFilter(cfg Config) string {
	var parts []string
	if cfg.EnableARP {
		parts = append(parts, "arp")
	}
	if cfg.EnableDHCP {
		parts = append(parts, "(udp and (port 67 or port 68))")
	}
	if cfg.EnableMDNS {
		parts = append(parts, "(udp and port 5353)")
	}
	if cfg.EnableSSDP {
		parts = append(parts, "(udp and port 1900)")
	}
	return strings.Join(parts, " or ")
}
