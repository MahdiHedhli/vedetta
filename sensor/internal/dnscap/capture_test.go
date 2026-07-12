//go:build !windows

package dnscap

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParsePacketAcceptsDNSQueries(t *testing.T) {
	c := &Capturer{}

	query := c.parsePacket(dnsPacket(t, false))
	if query == nil {
		t.Fatal("expected DNS query")
	}
	if query.Domain != "example.com" {
		t.Fatalf("expected query domain, got %q", query.Domain)
	}
	if query.ClientIP != "192.168.1.25" {
		t.Fatalf("expected client IP, got %q", query.ClientIP)
	}
	if query.ServerIP != "192.168.1.1" {
		t.Fatalf("expected server IP, got %q", query.ServerIP)
	}
	if query.Direction != "query" || query.RCode != "" {
		t.Fatalf("query wire semantics = direction %q rcode %q", query.Direction, query.RCode)
	}
}

func TestParsePacketParsesDNSResponsesForActionability(t *testing.T) {
	c := &Capturer{}

	query := c.parsePacket(dnsPacket(t, true))
	if query == nil {
		t.Fatal("expected DNS response to be parsed (for answers/destinations)")
	}
	if query.Domain != "example.com" {
		t.Fatalf("expected domain, got %q", query.Domain)
	}
	// For responses, client should be the destination of the response packet (original querier)
	if query.ClientIP != "192.168.1.25" {
		t.Fatalf("expected client IP (dst of response) to be 192.168.1.25, got %q", query.ClientIP)
	}
	if query.ServerIP != "192.168.1.1" {
		t.Fatalf("expected server IP, got %q", query.ServerIP)
	}
	if len(query.Answers) == 0 || query.Answers[0] != "192.0.2.34" {
		t.Fatalf("expected answers to include resolved IP, got %+v", query.Answers)
	}
	if query.Direction != "response" || query.RCode == "" {
		t.Fatalf("response wire semantics = direction %q rcode %q", query.Direction, query.RCode)
	}
}

func TestParsePacketUsesCNAMETargetRatherThanRecordOwner(t *testing.T) {
	c := &Capturer{}
	query := c.parsePacket(dnsPacketWithAnswers(t, true, []layers.DNSResourceRecord{{
		Name:  []byte("portal.example"),
		Type:  layers.DNSTypeCNAME,
		Class: layers.DNSClassIN,
		CNAME: []byte("c2.badzone.example"),
	}}))
	if query == nil {
		t.Fatal("expected CNAME response")
	}
	if len(query.Answers) != 1 || query.Answers[0] != "c2.badzone.example" {
		t.Fatalf("CNAME target was not preserved for Core observables: %+v", query.Answers)
	}
}

func TestCapturerStopJoinsInFlightCallback(t *testing.T) {
	handle := newFakePacketCaptureHandle()
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	var callbacks atomic.Int32
	c := &Capturer{
		iface:        "synthetic0",
		filter:       "udp port 53",
		batchSize:    1,
		batchTimeout: time.Hour,
		openLive: func(string, int32, bool, time.Duration) (packetCaptureHandle, error) {
			return handle, nil
		},
		onQuery: func(Query) {
			callbacks.Add(1)
			close(callbackStarted)
			<-releaseCallback
		},
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	packet := dnsPacket(t, false)
	handle.packets <- fakeCapturedPacket{
		data: packet.Data(),
		info: gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(packet.Data()), Length: len(packet.Data())},
	}
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("capture callback did not start")
	}

	stopDone := make(chan struct{})
	secondStopDone := make(chan struct{})
	go func() {
		c.Stop()
		close(stopDone)
	}()
	select {
	case <-handle.closed:
	case <-time.After(time.Second):
		t.Fatal("Stop did not signal the capture handle")
	}
	go func() {
		c.Stop()
		close(secondStopDone)
	}()
	select {
	case <-stopDone:
		t.Fatal("Stop returned while callback was still running")
	default:
	}
	select {
	case <-secondStopDone:
		t.Fatal("concurrent Stop returned while callback was still running")
	default:
	}
	close(releaseCallback)
	for index, done := range []<-chan struct{}{stopDone, secondStopDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("Stop caller %d did not join the released callback", index+1)
		}
	}
	if got := callbacks.Load(); got != 1 {
		t.Fatalf("callbacks after Stop = %d, want 1", got)
	}
	// A later repeated shutdown must not close the stop channel a second time.
	c.Stop()
}

type fakeCapturedPacket struct {
	data []byte
	info gopacket.CaptureInfo
}

type fakePacketCaptureHandle struct {
	packets   chan fakeCapturedPacket
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakePacketCaptureHandle() *fakePacketCaptureHandle {
	return &fakePacketCaptureHandle{
		packets: make(chan fakeCapturedPacket, 1),
		closed:  make(chan struct{}),
	}
}

func (h *fakePacketCaptureHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	select {
	case packet := <-h.packets:
		return packet.data, packet.info, nil
	case <-h.closed:
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
}

func (*fakePacketCaptureHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (*fakePacketCaptureHandle) SetBPFFilter(string) error { return nil }
func (h *fakePacketCaptureHandle) Close() {
	h.closeOnce.Do(func() { close(h.closed) })
}

func dnsPacket(t *testing.T, response bool) gopacket.Packet {
	t.Helper()
	var answers []layers.DNSResourceRecord
	if response {
		answers = []layers.DNSResourceRecord{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    net.ParseIP("192.0.2.34").To4(),
		}}
	}
	return dnsPacketWithAnswers(t, response, answers)
}

func dnsPacketWithAnswers(t *testing.T, response bool, answers []layers.DNSResourceRecord) gopacket.Packet {
	t.Helper()

	srcIP := net.ParseIP("192.168.1.25").To4()
	dstIP := net.ParseIP("192.168.1.1").To4()
	srcPort := layers.UDPPort(53530)
	dstPort := layers.UDPPort(53)
	if response {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}

	dns := &layers.DNS{
		ID:           1,
		QR:           response,
		OpCode:       layers.DNSOpCodeQuery,
		RD:           true,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
		ANCount: uint16(len(answers)),
		Answers: answers,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	},
		&layers.Ethernet{
			SrcMAC:       mustDNSMAC(t, "aa:bb:cc:dd:ee:ff"),
			DstMAC:       mustDNSMAC(t, "11:22:33:44:55:66"),
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip,
		udp,
		dns,
	); err != nil {
		t.Fatalf("serialize DNS packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mustDNSMAC(t *testing.T, raw string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(raw)
	if err != nil {
		t.Fatalf("parse MAC %q: %v", raw, err)
	}
	return mac
}
