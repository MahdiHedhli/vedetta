//go:build windows

package netscan

import (
	"reflect"
	"testing"
)

func ipv4DWORD(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

func TestNeighborsFromIPNetRowsRetainsStateAndByteOrder(t *testing.T) {
	rows := []mibIPNetRow{
		{index: 1_000_000_001, physAddrLen: 6, physAddr: [8]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, address: ipv4DWORD(192, 0, 2, 7), entryType: mibIPNetTypeDynamic},
		{index: 1_000_000_002, physAddrLen: 6, physAddr: [8]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02}, address: ipv4DWORD(198, 51, 100, 9), entryType: 4},
		{physAddrLen: 6, physAddr: [8]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x03}, address: ipv4DWORD(203, 0, 113, 10), entryType: mibIPNetTypeInvalid},
		{physAddrLen: 5, physAddr: [8]byte{0x00, 0x00, 0x5e, 0x00, 0x53}, address: ipv4DWORD(203, 0, 113, 11), entryType: mibIPNetTypeDynamic},
		{physAddrLen: 6, physAddr: [8]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}, address: ipv4DWORD(203, 0, 113, 12), entryType: mibIPNetTypeDynamic},
	}
	want := []neighbor{
		{ip: "192.0.2.7", mac: "00:00:5e:00:53:01", ifIndex: 1_000_000_001, state: neighborStateDynamic},
		{ip: "198.51.100.9", mac: "00:00:5e:00:53:02", ifIndex: 1_000_000_002, state: neighborStateStatic},
	}
	if got := neighborsFromIPNetRows(rows); !reflect.DeepEqual(got, want) {
		t.Fatalf("neighborsFromIPNetRows() = %#v, want %#v", got, want)
	}
}

func TestWindowsSourceScopesDuplicateIPByNativeInterfaceIndex(t *testing.T) {
	scope, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var emitted []DiscoveredHost
	s := NewSource(SourceConfig{
		CIDR: "192.0.2.0/24",
		readNeighbors: func() ([]neighbor, error) {
			return []neighbor{
				{ip: "192.0.2.81", mac: "00:00:5e:00:53:81", ifIndex: 17, state: neighborStateDynamic},
				{ip: "192.0.2.81", mac: "00:00:5e:00:53:82", ifIndex: 23, state: neighborStateDynamic},
			}, nil
		},
		OnHost: func(host DiscoveredHost) { emitted = append(emitted, host) },
	})
	s.scope = scope
	s.selectedInterface = "Ethernet"
	s.selectedIfIndex = 17
	s.linkNetwork = mustTestNetwork(t, "192.0.2.0/24")
	s.readOnce()
	if len(emitted) != 1 || emitted[0].MACAddress != "00:00:5e:00:53:81" {
		t.Fatalf("overlapping Windows interface rows were mixed: %+v", emitted)
	}
}
