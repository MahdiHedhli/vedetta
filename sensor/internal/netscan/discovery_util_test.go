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
		{"192.0.2.255", "aa:bb:cc:dd:ee:ff", false},     // directed broadcast
		{"255.255.255.255", "ff:ff:ff:ff:ff:ff", false}, // broadcast
		{"224.0.0.251", "01:00:5e:00:00:fb", false},     // IPv4 multicast (mDNS)
		{"192.0.2.9", "ff:ff:ff:ff:ff:ff", false},       // broadcast MAC
	}
	for _, c := range cases {
		if got := isRealNeighbor(c.ip, c.mac); got != c.want {
			t.Errorf("isRealNeighbor(%s, %s) = %v, want %v", c.ip, c.mac, got, c.want)
		}
	}
}
