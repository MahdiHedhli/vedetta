package passive

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseARP(t *testing.T) {
	packet := newTestPacket(t,
		&layers.Ethernet{
			SrcMAC:       mustMAC(t, "aa:bb:cc:dd:ee:ff"),
			DstMAC:       mustMAC(t, "ff:ff:ff:ff:ff:ff"),
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   []byte(mustMAC(t, "aa:bb:cc:dd:ee:ff")),
			SourceProtAddress: []byte(net.ParseIP("192.168.1.10").To4()),
			DstHwAddress:      []byte(mustMAC(t, "11:22:33:44:55:66")),
			DstProtAddress:    []byte(net.ParseIP("192.168.1.1").To4()),
		},
	)

	hosts := parseARP(packet)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].IPAddress != "192.168.1.10" {
		t.Fatalf("expected ARP IP, got %q", hosts[0].IPAddress)
	}
	if hosts[0].MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("expected ARP MAC, got %q", hosts[0].MACAddress)
	}
}

func TestParseDHCPv4(t *testing.T) {
	host := hostFromDHCPv4(&layers.DHCPv4{
		ClientHWAddr: mustMAC(t, "aa:bb:cc:dd:ee:ff"),
		YourClientIP: net.ParseIP("192.168.1.23").To4(),
		Options: layers.DHCPOptions{
			{Type: layers.DHCPOptHostname, Data: []byte("camera.local")},
		},
	}, "192.168.1.1")
	if host == nil {
		t.Fatal("expected DHCP host")
	}
	if host.IPAddress != "192.168.1.23" {
		t.Fatalf("expected DHCP IP, got %q", host.IPAddress)
	}
	if host.Hostname != "camera.local" {
		t.Fatalf("expected DHCP hostname, got %q", host.Hostname)
	}
}

func TestParseMDNS(t *testing.T) {
	hosts := hostsFromMDNS(&layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("printer.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    net.ParseIP("192.168.1.60").To4(),
			},
		},
	}, "192.168.1.50")
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].IPAddress != "192.168.1.60" {
		t.Fatalf("expected mDNS IP, got %q", hosts[0].IPAddress)
	}
	if hosts[0].Hostname != "printer.local" {
		t.Fatalf("expected mDNS hostname, got %q", hosts[0].Hostname)
	}
}

func TestParseSSDP(t *testing.T) {
	host := hostFromSSDPPayload([]byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: TestVendor/1.0 UPnP/1.1\r\nLOCATION: http://device.local/description.xml\r\n\r\n"), "192.168.1.70")
	if host == nil {
		t.Fatal("expected SSDP host")
	}
	if host.IPAddress != "192.168.1.70" {
		t.Fatalf("expected SSDP source IP, got %q", host.IPAddress)
	}
	if host.Hostname != "device.local" {
		t.Fatalf("expected SSDP hostname, got %q", host.Hostname)
	}
	if host.Vendor == "" {
		t.Fatal("expected SSDP vendor string")
	}
}

func newTestPacket(t *testing.T, serializableLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, serializableLayers...); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mustMAC(t *testing.T, raw string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(raw)
	if err != nil {
		t.Fatalf("parse mac %q: %v", raw, err)
	}
	return mac
}
