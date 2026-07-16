package netscan

import (
	"reflect"
	"testing"
)

// Fixtures use RFC 5737 / RFC 3849 documentation addresses per the spec 006 env-data
// rule (plus standard well-known broadcast/multicast constants).
func TestEnumerateHosts(t *testing.T) {
	got, err := enumerateHosts("192.0.2.0/30")
	if err != nil {
		t.Fatalf("enumerateHosts /30: %v", err)
	}
	if want := []string{"192.0.2.1", "192.0.2.2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("enumerateHosts(/30) = %v, want %v", got, want)
	}

	if got, _ := enumerateHosts("203.0.113.7"); !reflect.DeepEqual(got, []string{"203.0.113.7"}) {
		t.Errorf("enumerateHosts(bare IPv4) = %v", got)
	}
	if got, err := enumerateHosts("203.0.113.7/32"); err != nil || !reflect.DeepEqual(got, []string{"203.0.113.7"}) {
		t.Errorf("enumerateHosts(/32) = %v, %v; want exact target", got, err)
	}
	if got, err := enumerateHosts("203.0.113.6/31"); err != nil || !reflect.DeepEqual(got, []string{"203.0.113.6", "203.0.113.7"}) {
		t.Errorf("enumerateHosts(/31) = %v, %v; want both RFC 3021 endpoints", got, err)
	}
	if got, err := enumerateHosts("192.0.2.1,3-4"); err != nil || !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.3", "192.0.2.4"}) {
		t.Errorf("enumerateHosts(range/list) = %v, %v", got, err)
	}
	if got, _ := enumerateHosts("2001:db8::/64"); got != nil {
		t.Errorf("enumerateHosts(IPv6) = %v, want nil (IPv4-only v1)", got)
	}
	if got, _ := enumerateHosts("::ffff:192.0.2.7"); got != nil {
		t.Errorf("enumerateHosts(mapped IPv6) = %v, want nil", got)
	}
	if got, _ := enumerateHosts("::ffff:192.0.2.7/128"); got != nil {
		t.Errorf("enumerateHosts(mapped IPv6 CIDR) = %v, want nil", got)
	}
	if _, err := enumerateHosts("198.51.100.0/8"); err == nil {
		t.Error("enumerateHosts(/8) should error as too wide")
	}
	// Oversized ranges are rejected, not silently truncated: /21 (2046 hosts) errors,
	// /22 (1022 hosts, under the 1024 cap) is allowed.
	if _, err := enumerateHosts("198.51.100.0/21"); err == nil {
		t.Error("enumerateHosts(/21) should error (over the sweep cap), not truncate")
	}
	if got, err := enumerateHosts("198.51.104.0/22"); err != nil || len(got) != 1022 {
		t.Errorf("enumerateHosts(/22) = %d hosts, err %v; want 1022, nil", len(got), err)
	}
	if got, _ := enumerateHosts("198.51.100.0/24"); len(got) != 254 {
		t.Errorf("enumerateHosts(/24) count = %d, want 254", len(got))
	}
	if _, err := enumerateHosts("not-a-cidr"); err == nil {
		t.Error("enumerateHosts(invalid) should error")
	}
}

func TestSourceBoundWindowsTargetGrammar(t *testing.T) {
	for _, target := range []string{"192.0.2.7", "203.0.113.0/22"} {
		if err := validateSourceBoundWindowsTarget(target); err != nil {
			t.Errorf("source-bound Windows target %q rejected: %v", target, err)
		}
	}
	for _, target := range []string{"192.0.2.1-20", "192.0.2.1,3-4"} {
		if err := validateSourceBoundWindowsTarget(target); err == nil {
			t.Errorf("source-bound Windows range/list %q accepted", target)
		}
	}
}

func TestIPv4TargetContainsOnlyRequestedAddresses(t *testing.T) {
	cases := []struct {
		target, candidate string
		want              bool
	}{
		{"192.0.2.7", "192.0.2.7", true},
		{"192.0.2.7", "192.0.2.8", false},
		{"192.0.2.0/30", "192.0.2.2", true},
		{"192.0.2.0/30", "198.51.100.2", false},
		{"192.0.2.1,3-4", "192.0.2.3", true},
		{"192.0.2.1,3-4", "192.0.2.2", false},
		{"192.0-4.0-255.1", "192.4.255.1", true}, // membership does not expand >1024 addresses
		{"192.0-4.0-255.1", "192.5.255.1", false},
		{"999.0.0.1", "192.0.0.1", false},
		{"::ffff:192.0.2.7", "192.0.2.7", false},
		{"::ffff:192.0.2.7/128", "192.0.2.7", false},
	}
	for _, tc := range cases {
		if got := ipv4TargetContains(tc.target, tc.candidate); got != tc.want {
			t.Errorf("ipv4TargetContains(%q, %q) = %v, want %v", tc.target, tc.candidate, got, tc.want)
		}
	}
}

func TestNmapRangeValidationFailsClosed(t *testing.T) {
	if got := nmapRangeBreadth("192.0.2.1,3-4"); got != 3 {
		t.Fatalf("range/list breadth = %d, want 3", got)
	}
	for _, target := range []string{"999.0.0.1", "192.0.2.1-999", "192.0.2.9-1"} {
		if got := nmapRangeBreadth(target); got <= maxScanAddresses {
			t.Errorf("invalid target %q breadth = %d, want fail-closed sentinel", target, got)
		}
	}
}

func TestIsRealNeighbor(t *testing.T) {
	cases := []struct {
		ip, mac string
		want    bool
	}{
		{"192.0.2.5", "aa:bb:cc:dd:ee:ff", true},
		{"192.0.2.255", "aa:bb:cc:dd:ee:ff", true},      // prefix decides whether this is broadcast
		{"255.255.255.255", "ff:ff:ff:ff:ff:ff", false}, // broadcast
		{"224.0.0.251", "01:00:5e:00:00:fb", false},     // IPv4 multicast (mDNS)
		{"192.0.2.9", "ff:ff:ff:ff:ff:ff", false},       // broadcast MAC
		{"192.0.2.9", "01:80:c2:00:00:00", false},       // generic multicast MAC
		{"192.0.2.9", "00:00:00:00:00:00", false},       // unspecified MAC
		{"192.0.2.9", "00:00:5e:00:53:00:01:02", false}, // EUI-64 is not an Ethernet MAC
		{"0.0.0.0", "00:00:5e:00:53:01", false},
		{"127.0.0.1", "00:00:5e:00:53:01", false},
		{"2001:db8::1", "00:00:5e:00:53:01", false},
	}
	for _, c := range cases {
		if got := isRealNeighbor(c.ip, c.mac); got != c.want {
			t.Errorf("isRealNeighbor(%s, %s) = %v, want %v", c.ip, c.mac, got, c.want)
		}
	}
}

func TestIPv4ScopeContainsHostUsesActualPrefix(t *testing.T) {
	tests := []struct {
		scope string
		ip    string
		want  bool
	}{
		{"192.0.2.0/23", "192.0.2.255", true},  // ordinary host in a /23
		{"192.0.2.0/24", "192.0.2.255", false}, // /24 broadcast
		{"192.0.2.0/26", "192.0.2.63", false},  // /26 broadcast
		{"192.0.2.0/26", "192.0.2.62", true},
		{"192.0.2.0/26", "192.0.2.64", false}, // outside this /26
		{"192.0.2.0/31", "192.0.2.0", true},   // RFC 3021 endpoints
		{"192.0.2.0/31", "192.0.2.1", true},
		{"192.0.2.7", "192.0.2.7", true},
		{"192.0.2.7", "192.0.2.8", false},
	}
	for _, tt := range tests {
		scope, err := parseIPv4Scope(tt.scope)
		if err != nil {
			t.Fatalf("parseIPv4Scope(%q): %v", tt.scope, err)
		}
		if got := scope.containsHost(tt.ip); got != tt.want {
			t.Errorf("scope %s containsHost(%s) = %v, want %v", tt.scope, tt.ip, got, tt.want)
		}
	}
}

func TestParseIPv4ScopeRejectsInvalidAndIPv6(t *testing.T) {
	for _, value := range []string{"", "not-a-cidr", "2001:db8::/64", "2001:db8::1"} {
		if _, err := parseIPv4Scope(value); err == nil {
			t.Errorf("parseIPv4Scope(%q) unexpectedly succeeded", value)
		}
	}
}
