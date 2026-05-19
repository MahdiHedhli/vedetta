package dnscap

import (
	"net"
	"testing"

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
}

func TestParsePacketIgnoresDNSResponses(t *testing.T) {
	c := &Capturer{}

	if query := c.parsePacket(dnsPacket(t, true)); query != nil {
		t.Fatalf("expected DNS response to be ignored, got %+v", query)
	}
}

func dnsPacket(t *testing.T, response bool) gopacket.Packet {
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
	}
	if response {
		dns.ANCount = 1
		dns.Answers = []layers.DNSResourceRecord{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    net.ParseIP("93.184.216.34").To4(),
		}}
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
