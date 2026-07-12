package dnscap

import (
	"net"
	"testing"
)

// TestPrimaryHostIP guards the mechanism the Windows ETW capturer relies on to stamp
// a client IP on every query. Core silently drops DNS with an empty client IP, so a
// regression here would make every Windows sensor's DNS vanish (the bug the Win 11
// end-to-end test caught). Any host running the test suite has a route, so this must
// return a parseable, non-loopback, non-unspecified IP.
func TestPrimaryHostIP(t *testing.T) {
	got := primaryHostIP()
	if got == "" {
		t.Fatal("primaryHostIP() returned empty — Windows DNS would be dropped by Core")
	}
	ip := net.ParseIP(got)
	if ip == nil {
		t.Fatalf("primaryHostIP() = %q, not a valid IP", got)
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		t.Fatalf("primaryHostIP() = %q, want a real routable host address", got)
	}
}
