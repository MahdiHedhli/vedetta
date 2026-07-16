//go:build darwin || freebsd || netbsd || openbsd

package netscan

import (
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// rtMsg builds a synthetic ARP route message: a DST Inet4Addr + a GATEWAY LinkAddr at
// the canonical RTAX indices, with the given flags.
func rtMsg(flags int, ip [4]byte, mac []byte, iface string) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_GATEWAY+1)
	addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: ip}
	addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: 17, Name: iface, Addr: mac}
	return &route.RouteMessage{Flags: flags, Addrs: addrs}
}

func TestNeighborsFromRIB(t *testing.T) {
	msgs := []route.Message{
		// kept: a resolved ARP entry (RTF_LLINFO), uppercase-agnostic MAC bytes.
		rtMsg(unix.RTF_LLINFO, [4]byte{192, 0, 2, 10}, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, "en0"),
		// dropped: no RTF_LLINFO (a plain gateway route, not a neighbor).
		rtMsg(0, [4]byte{192, 0, 2, 1}, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}, "en0"),
		// dropped: multicast MAC (01:00:5e:..) via isRealNeighbor.
		rtMsg(unix.RTF_LLINFO, [4]byte{224, 0, 0, 251}, []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, "en0"),
		// dropped: empty link-layer address.
		rtMsg(unix.RTF_LLINFO, [4]byte{192, 0, 2, 12}, nil, "en0"),
		// kept: a second resolved entry on another interface.
		rtMsg(unix.RTF_LLINFO, [4]byte{192, 0, 2, 20}, []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x20}, "en1"),
		// retained but marked static so Source will not treat it as liveness.
		rtMsg(unix.RTF_LLINFO|unix.RTF_STATIC, [4]byte{192, 0, 2, 30}, []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x30}, "en0"),
	}
	got := neighborsFromRIB(msgs)
	want := map[string]neighbor{
		"192.0.2.10": {ip: "192.0.2.10", mac: "aa:bb:cc:dd:ee:01", iface: "en0", ifIndex: 17, state: neighborStateDynamic},
		"192.0.2.20": {ip: "192.0.2.20", mac: "00:00:5e:00:53:20", iface: "en1", ifIndex: 17, state: neighborStateDynamic},
		"192.0.2.30": {ip: "192.0.2.30", mac: "00:00:5e:00:53:30", iface: "en0", ifIndex: 17, state: neighborStateStatic},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d neighbors %+v, want %d", len(got), got, len(want))
	}
	for _, n := range got {
		w, ok := want[n.ip]
		if !ok {
			t.Errorf("unexpected neighbor %+v (non-LLINFO/multicast/empty-MAC must be dropped)", n)
			continue
		}
		if n != w {
			t.Errorf("neighbor %s = %+v, want %+v", n.ip, n, w)
		}
	}
}
