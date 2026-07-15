//go:build windows

package netscan

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	mibIPNetTypeInvalid = 2
	mibIPNetTypeDynamic = 3
)

// mibIPNetRow mirrors Windows' MIB_IPNETROW. GetIpNetTable is used instead of
// launching arp.exe from the LocalSystem service, avoiding PATH lookup and making
// command/API failures observable.
type mibIPNetRow struct {
	index       uint32
	physAddrLen uint32
	physAddr    [8]byte
	address     uint32
	entryType   uint32
}

var procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")

// readNeighbors reads the IPv4 neighbor table through iphlpapi. It retains the
// interface and dynamic/static state; the ARP source emits only dynamic entries.
func readNeighbors() ([]neighbor, error) {
	// The table can grow between the size query and fetch. Retry that documented
	// race a few times; genuine API failures still propagate to the caller.
	for attempt := 0; attempt < 3; attempt++ {
		var size uint32
		status, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 1)
		errno := windows.Errno(status)
		if errno == windows.ERROR_NO_DATA {
			return nil, nil
		}
		if status != 0 && errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, fmt.Errorf("GetIpNetTable size: %w", errno)
		}
		if size < uint32(unsafe.Sizeof(uint32(0))) {
			return nil, nil
		}
		buf := make([]byte, size)
		status, _, _ = procGetIpNetTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
		)
		errno = windows.Errno(status)
		if errno == windows.ERROR_NO_DATA {
			return nil, nil
		}
		if errno == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("GetIpNetTable: %w", errno)
		}
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		rowSize := uintptr(unsafe.Sizeof(mibIPNetRow{}))
		offset := uintptr(unsafe.Sizeof(uint32(0)))
		rows := make([]mibIPNetRow, 0, count)
		for i := uint32(0); i < count; i++ {
			start := offset + uintptr(i)*rowSize
			if start+rowSize > uintptr(len(buf)) {
				return nil, fmt.Errorf("GetIpNetTable returned truncated row %d of %d", i+1, count)
			}
			rows = append(rows, *(*mibIPNetRow)(unsafe.Pointer(&buf[start])))
		}
		return neighborsFromIPNetRows(rows), nil
	}
	return nil, fmt.Errorf("GetIpNetTable changed during 3 consecutive reads")
}

func neighborsFromIPNetRows(rows []mibIPNetRow) []neighbor {
	out := make([]neighbor, 0, len(rows))
	for _, row := range rows {
		if row.entryType == mibIPNetTypeInvalid || row.physAddrLen != 6 {
			continue
		}
		ip := net.IPv4(byte(row.address), byte(row.address>>8), byte(row.address>>16), byte(row.address>>24)).String()
		mac := strings.ToLower(net.HardwareAddr(row.physAddr[:row.physAddrLen]).String())
		if !isRealNeighbor(ip, mac) {
			continue
		}
		state := neighborStateStatic
		if row.entryType == mibIPNetTypeDynamic {
			state = neighborStateDynamic
		}
		iface := ""
		if ifi, err := net.InterfaceByIndex(int(row.index)); err == nil {
			iface = ifi.Name
		}
		out = append(out, neighbor{ip: ip, mac: mac, iface: iface, ifIndex: int(row.index), state: state})
	}
	return out
}
