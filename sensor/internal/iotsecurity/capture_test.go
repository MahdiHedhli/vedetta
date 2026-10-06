//go:build !windows

package iotsecurity

import (
	"net"
	"testing"
)

func TestCaptureSubjectScopeAndIdleStop(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.0.2.0/24")
	capturer := &Capturer{networks: []*net.IPNet{subnet}}
	if !capturer.subjectAllowed("192.0.2.10") || capturer.subjectAllowed("203.0.113.1") || capturer.subjectAllowed("not-an-ip") {
		t.Fatal("logical subject scope accepted an unrelated endpoint")
	}
	capturer.Stop()
	capturer.Stop()
	if CaptureFilter != "udp and (port 9034 or port 3478 or port 19302)" {
		t.Fatal("capture filter broadened beyond the declared feature")
	}
}

func TestCaptureAcceptsLiteralIPScope(t *testing.T) {
	for _, ip := range []string{"192.0.2.10", "2001:db8::10"} {
		capturer, err := NewCapturer(Config{Interface: "synthetic-no-capture-interface", CIDR: ip})
		if err != nil || !capturer.subjectAllowed(ip) || capturer.subjectAllowed("203.0.113.10") {
			t.Fatalf("literal IP scope %s failed: %v", ip, err)
		}
	}
}
