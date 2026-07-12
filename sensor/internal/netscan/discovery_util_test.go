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
	if got, _ := enumerateHosts("2001:db8::/64"); got != nil {
		t.Errorf("enumerateHosts(IPv6) = %v, want nil (IPv4-only v1)", got)
	}
	if _, err := enumerateHosts("198.51.100.0/8"); err == nil {
		t.Error("enumerateHosts(/8) should error as too wide")
	}
	if got, _ := enumerateHosts("198.51.100.0/24"); len(got) != 254 {
		t.Errorf("enumerateHosts(/24) count = %d, want 254", len(got))
	}
	if _, err := enumerateHosts("not-a-cidr"); err == nil {
		t.Error("enumerateHosts(invalid) should error")
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
