package dnscap

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
)

// Capturer performs passive DNS query capture using libpcap.
type Capturer struct {
	iface        string
	filter       string
	batchSize    int
	batchTimeout time.Duration
	handler      *pcap.Handle
	mu           sync.Mutex
	stopCh       chan struct{}
	doneCh       chan struct{}
	running      bool
	onQuery      func(Query)
}

// Query represents a captured DNS query.
type Query struct {
	Timestamp time.Time
	Domain    string
	QueryType string
	ClientIP  string
	ServerIP  string
	Blocked   bool
	Source    string // e.g., "passive_capture"
}

// Config contains settings for DNS capture.
type Config struct {
	Interface    string        // Network interface to capture on (or "auto" for best match)
	CoreURL      string        // Vedetta Core URL used as a route hint
	CIDR         string        // Scan CIDR used to prefer the local LAN interface
	Filter       string        // BPF filter string (optional, overrides default)
	BatchSize    int           // Number of queries to batch before sending
	BatchTimeout time.Duration // Max time to wait before sending a batch
	OnQuery      func(Query)   // Callback for each captured query
}

// NewCapturer creates a new passive DNS capturer.
func NewCapturer(cfg Config) (*Capturer, error) {
	iface := cfg.Interface
	if iface == "" || iface == "auto" {
		selection, err := netinfo.SelectCaptureInterface(netinfo.CaptureSelectionOptions{
			Preferred: cfg.Interface,
			CoreURL:   cfg.CoreURL,
			ScanCIDR:  cfg.CIDR,
			Purpose:   "dns capture",
		})
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
		iface = selection.Name
		log.Printf("dnscap: %s", netinfo.FormatCaptureSelection(selection, "dns capture"))
	}

	filter := cfg.Filter
	if filter == "" {
		filter = "udp port 53 or tcp port 53"
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = 10 * time.Second
	}

	return &Capturer{
		iface:        iface,
		filter:       filter,
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		onQuery:      cfg.OnQuery,
	}, nil
}

// Start begins packet capture in a background goroutine.
func (c *Capturer) Start() error {
	if c.running {
		return fmt.Errorf("capturer already running")
	}

	// Open live capture handle
	handle, err := pcap.OpenLive(c.iface, 65535, false, 30*time.Second)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", c.iface, err)
	}

	// Set BPF filter
	if err := handle.SetBPFFilter(c.filter); err != nil {
		handle.Close()
		return fmt.Errorf("set BPF filter: %w", err)
	}

	c.handler = handle
	c.running = true

	go c.run()
	log.Printf("dnscap: Capturer started on interface %s", c.iface)
	return nil
}

// Interface returns the active capture interface.
func (c *Capturer) Interface() string {
	return c.iface
}

// Stop gracefully stops packet capture.
func (c *Capturer) Stop() {
	if !c.running {
		return
	}
	close(c.stopCh)
	<-c.doneCh
	if c.handler != nil {
		c.handler.Close()
	}
	log.Printf("dnscap: Capturer stopped")
}

// run is the main capture loop.
func (c *Capturer) run() {
	defer close(c.doneCh)

	packetSource := gopacket.NewPacketSource(c.handler, c.handler.LinkType())
	packets := packetSource.Packets()

	ticker := time.NewTicker(c.batchTimeout)
	defer ticker.Stop()

	batch := make([]Query, 0, c.batchSize)
	batchMu := sync.Mutex{}

	// Packet processing goroutine
	go func() {
		for {
			select {
			case packet := <-packets:
				if packet == nil {
					return
				}
				if query := c.parsePacket(packet); query != nil {
					batchMu.Lock()
					batch = append(batch, *query)
					batchMu.Unlock()

					// Send immediately if batch is full
					if len(batch) >= c.batchSize {
						batchMu.Lock()
						c.sendBatch(batch)
						batch = make([]Query, 0, c.batchSize)
						batchMu.Unlock()
					}
				}
			case <-c.stopCh:
				return
			}
		}
	}()

	// Batch timeout loop
	for {
		select {
		case <-ticker.C:
			batchMu.Lock()
			if len(batch) > 0 {
				c.sendBatch(batch)
				batch = make([]Query, 0, c.batchSize)
			}
			batchMu.Unlock()
		case <-c.stopCh:
			// Final flush
			batchMu.Lock()
			if len(batch) > 0 {
				c.sendBatch(batch)
			}
			batchMu.Unlock()
			return
		}
	}
}

// parsePacket extracts DNS queries from a captured packet.
func (c *Capturer) parsePacket(packet gopacket.Packet) *Query {
	// Get IP layer
	ipv4, ipv6 := false, false
	var clientIP, serverIP string

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ipv4Layer := ip4.(*layers.IPv4)
		clientIP = ipv4Layer.SrcIP.String()
		serverIP = ipv4Layer.DstIP.String()
		ipv4 = true
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ipv6Layer := ip6.(*layers.IPv6)
		clientIP = ipv6Layer.SrcIP.String()
		serverIP = ipv6Layer.DstIP.String()
		ipv6 = true
	}

	if !ipv4 && !ipv6 {
		return nil
	}

	// Get DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dns := dnsLayer.(*layers.DNS)
	if len(dns.Questions) == 0 {
		return nil
	}

	// Extract first question
	q := dns.Questions[0]
	domain := string(q.Name)
	if domain != "" && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1] // Remove trailing dot
	}

	queryType := layers.DNSType(q.Type).String()

	return &Query{
		Timestamp: packet.Metadata().Timestamp,
		Domain:    domain,
		QueryType: queryType,
		ClientIP:  clientIP,
		ServerIP:  serverIP,
		Source:    "passive_capture",
	}
}

// sendBatch calls the callback for each query in the batch.
func (c *Capturer) sendBatch(batch []Query) {
	if c.onQuery == nil {
		return
	}
	for _, q := range batch {
		c.onQuery(q)
	}
}
