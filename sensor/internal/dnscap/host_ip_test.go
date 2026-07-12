package dnscap

import (
	"net"
	"testing"
)

// TestPrimaryHostIP guards the default-route fallback. Any host running the suite has
// a route, so this must return a parseable, non-loopback, non-unspecified IP.
func TestPrimaryHostIP(t *testing.T) {
	got := primaryHostIP()
	if got == "" {
		t.Fatal("primaryHostIP() returned empty — Windows DNS would be dropped by Core")
	}
	ip := net.ParseIP(got)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		t.Fatalf("primaryHostIP() = %q, want a real routable host address", got)
	}
}

// TestLanHostIPFallback: with a CIDR that contains none of the host's addresses,
// lanHostIP must still return a usable address (the default-route fallback), never
// empty — otherwise Core would drop every Windows DNS event.
func TestLanHostIPFallback(t *testing.T) {
	// 198.51.100.0/24 (RFC 5737 TEST-NET-2) won't be a real local subnet.
	if got := lanHostIP("198.51.100.0/24"); got == "" || net.ParseIP(got) == nil {
		t.Fatalf("lanHostIP(non-local cidr) = %q, want the default-route fallback", got)
	}
}

// TestIPInCIDR: the resolver prefers a local address inside the sensor's scan CIDR.
// Build the CIDR from the host's own primary IP so the match is deterministic; a
// bogus CIDR must yield "".
func TestIPInCIDR(t *testing.T) {
	if got := ipInCIDR("not-a-cidr"); got != "" {
		t.Fatalf("ipInCIDR(bogus) = %q, want empty", got)
	}
	self := primaryHostIP()
	ip := net.ParseIP(self)
	if ip == nil || ip.To4() == nil {
		t.Skipf("no IPv4 primary address (%q) to build a containing CIDR", self)
	}
	cidr := self + "/24" // a /24 around the host's own address contains it
	if got := ipInCIDR(cidr); got == "" {
		t.Fatalf("ipInCIDR(%q) = empty, want a local address inside it", cidr)
	}
}
