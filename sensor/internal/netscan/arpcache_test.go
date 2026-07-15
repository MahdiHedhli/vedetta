package netscan

import (
	"strings"
	"testing"
)

func TestParseProcNetARP(t *testing.T) {
	// Mirrors the real /proc/net/arp layout. Kept: two completed entries (one with an
	// uppercase MAC that must normalize) plus a permanent (0x6) entry. Dropped: the
	// incomplete (0x0) row, an IPv4-multicast row, an all-ones-MAC row, and a
	// short/garbage line. The .255 row is retained here because only Source knows
	// the configured prefix (it can be a valid host in a /23).
	const table = `IP address       HW type     Flags       HW address            Mask     Device
192.0.2.10       0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.0.2.11       0x1         0x2         AA:BB:CC:DD:EE:02     *        eth0
192.0.2.12       0x1         0x0         00:00:00:00:00:00     *        eth0
239.0.0.1        0x1         0x2         01:00:5e:00:00:01     *        eth0
192.0.2.255      0x1         0x2         aa:bb:cc:dd:ee:03     *        eth0
198.51.100.7     0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
short garbage line
192.0.2.14       0x1         0x6         aa:bb:cc:dd:ee:04     *        wlan0
`
	got := parseProcNetARP(strings.NewReader(table))
	want := map[string]neighbor{
		"192.0.2.10":  {ip: "192.0.2.10", mac: "aa:bb:cc:dd:ee:01", iface: "eth0", state: neighborStateDynamic},
		"192.0.2.11":  {ip: "192.0.2.11", mac: "aa:bb:cc:dd:ee:02", iface: "eth0", state: neighborStateDynamic}, // uppercase normalized
		"192.0.2.255": {ip: "192.0.2.255", mac: "aa:bb:cc:dd:ee:03", iface: "eth0", state: neighborStateDynamic},
		"192.0.2.14":  {ip: "192.0.2.14", mac: "aa:bb:cc:dd:ee:04", iface: "wlan0", state: neighborStateStatic}, // permanent retained as non-liveness state
	}
	if len(got) != len(want) {
		t.Fatalf("got %d neighbors %+v, want %d", len(got), got, len(want))
	}
	for _, n := range got {
		w, ok := want[n.ip]
		if !ok {
			t.Errorf("unexpected neighbor %+v (incomplete/broadcast/multicast should be dropped)", n)
			continue
		}
		if n != w {
			t.Errorf("neighbor %s = %+v, want %+v", n.ip, n, w)
		}
	}
}

func TestParseProcNetARP_EmptyAndHeaderOnly(t *testing.T) {
	if got := parseProcNetARP(strings.NewReader("")); len(got) != 0 {
		t.Errorf("empty input: got %+v, want none", got)
	}
	const headerOnly = "IP address       HW type     Flags       HW address            Mask     Device\n"
	if got := parseProcNetARP(strings.NewReader(headerOnly)); len(got) != 0 {
		t.Errorf("header-only: got %+v, want none", got)
	}
}
