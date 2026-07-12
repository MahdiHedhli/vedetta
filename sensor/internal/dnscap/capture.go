//go:build !windows

package dnscap

import (
	"fmt"
	"log"
	"strings"
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
	handler      packetCaptureHandle
	openLive     openCaptureFunc
	mu           sync.Mutex
	stopCh       chan struct{}
	doneCh       chan struct{}
	running      bool
	stopping     bool
	onQuery      func(Query)
}

type packetCaptureHandle interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
	SetBPFFilter(string) error
	Close()
}

type openCaptureFunc func(string, int32, bool, time.Duration) (packetCaptureHandle, error)

func openPCAPLive(device string, snaplen int32, promiscuous bool, timeout time.Duration) (packetCaptureHandle, error) {
	return pcap.OpenLive(device, snaplen, promiscuous, timeout)
}

// Query and Config are defined in types.go (shared across capture backends).

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
		openLive:     openPCAPLive,
		onQuery:      cfg.OnQuery,
	}, nil
}

// Start begins packet capture in a background goroutine.
func (c *Capturer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running || c.stopping {
		return fmt.Errorf("capturer already running")
	}

	// Open live capture handle
	opener := c.openLive
	if opener == nil {
		opener = openPCAPLive
	}
	handle, err := opener(c.iface, 65535, false, 30*time.Second)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", c.iface, err)
	}

	// Set BPF filter
	if err := handle.SetBPFFilter(c.filter); err != nil {
		handle.Close()
		return fmt.Errorf("set BPF filter: %w", err)
	}

	c.handler = handle
	c.stopCh = make(chan struct{})
	c.doneCh = make(chan struct{})
	c.running = true

	go c.run(handle, handle.LinkType(), c.stopCh, c.doneCh)
	log.Printf("dnscap: Capturer started on interface %s", c.iface)
	return nil
}

// Interface returns the active capture interface.
func (c *Capturer) Interface() string {
	return c.iface
}

// Stop gracefully stops packet capture.
func (c *Capturer) Stop() {
	c.mu.Lock()
	if !c.running && !c.stopping {
		c.mu.Unlock()
		return
	}
	done := c.doneCh
	var handle packetCaptureHandle
	if !c.stopping {
		c.stopping = true
		close(c.stopCh)
		handle = c.handler
		c.handler = nil
	}
	c.mu.Unlock()

	// Closing the handle unblocks PacketSource's reader immediately. Join the
	// capture loop before returning so callbacks cannot write to a delivery
	// channel after shutdown closes it.
	if handle != nil {
		handle.Close()
	}
	<-done

	c.mu.Lock()
	if c.doneCh == done {
		c.running = false
		c.stopping = false
	}
	c.mu.Unlock()
	log.Printf("dnscap: Capturer stopped")
}

// run is the main capture loop.
func (c *Capturer) run(handle packetCaptureHandle, linkType layers.LinkType, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)

	packetSource := gopacket.NewPacketSource(handle, linkType)
	packets := packetSource.Packets()

	ticker := time.NewTicker(c.batchTimeout)
	defer ticker.Stop()

	batch := make([]Query, 0, c.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.sendBatch(batch)
		batch = make([]Query, 0, c.batchSize)
	}

	// Packet handling and batch flushing share one joined goroutine. This makes
	// batch ownership explicit and removes the unsynchronized length check and
	// orphan packet worker that previously could outlive doneCh.
	for {
		select {
		case packet, ok := <-packets:
			if !ok || packet == nil {
				flush()
				return
			}
			if query := c.parsePacket(packet); query != nil {
				batch = append(batch, *query)
				if len(batch) >= c.batchSize {
					flush()
				}
			}
		case <-ticker.C:
			flush()
		case <-stop:
			flush()
			return
		}
	}
}

// parsePacket extracts DNS queries from a captured packet.
// For responses (QR=true), we attribute to the original client (dst IP of response packet)
// and collect answer records for destination/actionability info.
func (c *Capturer) parsePacket(packet gopacket.Packet) *Query {
	// Get IP layer
	ipv4, ipv6 := false, false
	var srcIP, dstIP string

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ipv4Layer := ip4.(*layers.IPv4)
		srcIP = ipv4Layer.SrcIP.String()
		dstIP = ipv4Layer.DstIP.String()
		ipv4 = true
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ipv6Layer := ip6.(*layers.IPv6)
		srcIP = ipv6Layer.SrcIP.String()
		dstIP = ipv6Layer.DstIP.String()
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

	query := &Query{
		ObservationID: NewObservationID(),
		Timestamp:     packet.Metadata().Timestamp,
		Domain:        domain,
		QueryType:     queryType,
		Source:        "passive_capture",
		// Process left empty for pure network pcap capture. Host-local deployments of the sensor
		// (or additional OS integration) can populate this for full "source process" actionability.
	}

	if dns.QR {
		query.Direction = "response"
		query.RCode = dns.ResponseCode.String()
		// This is a response packet. The original querier is the destination of this packet.
		query.ClientIP = dstIP
		query.ServerIP = srcIP // the resolver that answered
		// Collect answer targets for actionability. The record owner (Name) is
		// usually the queried domain; CNAME's actual target lives in RDATA/CNAME.
		for _, ans := range dns.Answers {
			if target := dnsAnswerTarget(ans); target != "" {
				query.Answers = append(query.Answers, target)
			}
		}
		// Also additionals sometimes carry useful info
		for _, ans := range dns.Additionals {
			if target := dnsAnswerTarget(ans); target != "" {
				query.Answers = append(query.Answers, target)
			}
		}
	} else {
		query.Direction = "query"
		// Query packet: client is source
		query.ClientIP = srcIP
		query.ServerIP = dstIP
		// Queries typically have no answers; answers come in responses
	}

	return query
}

func dnsAnswerTarget(answer layers.DNSResourceRecord) string {
	trimName := func(raw []byte) string {
		return strings.TrimSuffix(strings.TrimSpace(string(raw)), ".")
	}
	switch answer.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if answer.IP != nil && !answer.IP.IsUnspecified() {
			return answer.IP.String()
		}
	case layers.DNSTypeCNAME:
		return trimName(answer.CNAME)
	case layers.DNSTypeNS:
		return trimName(answer.NS)
	case layers.DNSTypePTR:
		return trimName(answer.PTR)
	case layers.DNSTypeMX:
		return trimName(answer.MX.Name)
	case layers.DNSTypeSRV:
		return trimName(answer.SRV.Name)
	}
	return ""
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
