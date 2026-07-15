package netscan

import (
	"net"
	"testing"
)

func TestVirtualInterfaceClassificationDoesNotReservePrivateLANRanges(t *testing.T) {
	for _, name := range []string{"eth0", "en0", "wlan0"} {
		if isVirtualInterface(name) {
			t.Fatalf("physical interface %q classified as virtual", name)
		}
	}

	// These are the interface identities, rather than their conventional address
	// ranges, that make the links virtual. In particular, an eth0 using either
	// 172.17-31/16 or 192.168.65/24 must remain eligible for LAN detection.
	for _, name := range []string{
		"docker0", "br-a1b2c3", "veth42", "virbr0", "vmnet8", "vboxnet0",
		"cni0", "flannel.1", "cali123", "tunl0", "vxlan.calico", "weave", "kube-ipvs0", "podman0",
		"vEthernet (Default Switch)", "WSL", "utun4", "tun0", "tap0", "tailscale0", "wg0", "ztabc123",
		"awdl0", "llw0", "gif0", "stf0", "bridge100",
	} {
		if !isVirtualInterface(name) {
			t.Fatalf("known virtual interface %q was not classified as virtual", name)
		}
	}
}

func TestDetectedSubnetKeepsPhysicalInterfacesInFormerDockerRanges(t *testing.T) {
	for _, tc := range []struct {
		address [4]byte
		prefix  int
	}{
		{address: [4]byte{172, 17, 42, 9}, prefix: 16},
		{address: [4]byte{172, 31, 42, 9}, prefix: 16},
		{address: [4]byte{192, 168, 65, 9}, prefix: 24},
	} {
		ip := net.IPv4(tc.address[0], tc.address[1], tc.address[2], tc.address[3])
		network := &net.IPNet{IP: ip, Mask: net.CIDRMask(tc.prefix, 32)}
		wantCIDR := (&net.IPNet{IP: ip.Mask(network.Mask), Mask: network.Mask}).String()
		got, ok := detectedIPv4Subnet("eth0", network)
		if !ok || got.CIDR != wantCIDR || got.IPAddress != ip.String() {
			t.Fatalf("eth0 %s candidate = %+v ok=%v, want retained as %s", ip, got, ok, wantCIDR)
		}
	}

	dockerNetwork := &net.IPNet{IP: net.IPv4(172, 17, 0, 1), Mask: net.CIDRMask(16, 32)}
	if got, ok := detectedIPv4Subnet("docker0", dockerNetwork); ok {
		t.Fatalf("docker identity unexpectedly retained: %+v", got)
	}
}
