package passive

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
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
			{Type: layers.DHCPOptParamsRequest, Data: []byte{1, 3, 6, 15, 119}},
			{Type: layers.DHCPOptClientID, Data: []byte{1, 0, 0, 94, 0, 83, 1}},
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
	if got := identityEvidenceValue(host.IdentityEvidence, "dhcp_option_55"); got != "1,3,6,15,119" {
		t.Fatalf("DHCP option 55 evidence = %q", got)
	}
	if got := identityEvidenceValue(host.IdentityEvidence, "dhcp_client_id"); got != "0100005e005301" {
		t.Fatalf("DHCP option 61 evidence = %q", got)
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
	host := hostFromSSDPPayload([]byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: TestVendor/1.0 UPnP/1.1\r\nLOCATION: http://device.local/description.xml\r\nUSN: uuid:00000000-0000-0000-0000-000000000053::urn:schemas-upnp-org:device:MediaRenderer:1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n"), "192.0.2.70")
	if host == nil {
		t.Fatal("expected SSDP host")
	}
	if host.IPAddress != "192.0.2.70" {
		t.Fatalf("expected SSDP source IP, got %q", host.IPAddress)
	}
	if host.Hostname != "device.local" {
		t.Fatalf("expected SSDP hostname, got %q", host.Hostname)
	}
	if host.Vendor == "" {
		t.Fatal("expected SSDP vendor string")
	}
	if got := identityEvidenceValue(host.IdentityEvidence, "ssdp_uuid"); got != "00000000-0000-0000-0000-000000000053" {
		t.Fatalf("SSDP UUID evidence = %q", got)
	}
	if got := identityEvidenceValue(host.IdentityEvidence, "ssdp_device_type"); got != "urn:schemas-upnp-org:device:MediaRenderer:1" {
		t.Fatalf("SSDP device-type evidence = %q", got)
	}
	if got := identityEvidenceValue(host.IdentityEvidence, "ssdp_server_token"); got != "TestVendor/1.0 UPnP/1.1" {
		t.Fatalf("SSDP server-token evidence = %q", got)
	}
}

func identityEvidenceValue(items []netscan.IdentityEvidence, kind string) string {
	for _, item := range items {
		if item.Type == kind {
			return item.Value
		}
	}
	return ""
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
