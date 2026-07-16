package netscan

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
)

type neighborState uint8

const (
	neighborStateUnknown neighborState = iota
	neighborStateDynamic
	neighborStateStatic
)

// neighbor is one resolved IP↔MAC entry read from the OS ARP/neighbor cache.
// Interface and dynamic/static state are retained so the source can scope evidence
// to the configured segment and refuse permanent mappings as liveness evidence.
type neighbor struct {
	ip      string
	mac     string
	iface   string
	ifIndex int
	state   neighborState
}

// linuxARPCompleteFlag is Linux ATF_COM (0x2): the neighbor entry is resolved. Only
// completed entries are kept; incomplete ones (flag 0x0, MAC 00:00:00:00:00:00) are
// skipped. Permanent entries (0x6 = ATF_COM|ATF_PERM) also carry this bit.
const linuxARPCompleteFlag = 0x2

// linuxARPPermanentFlag is Linux ATF_PERM (0x4). A permanent mapping can be
// useful configuration, but its presence does not prove the device is online.
const linuxARPPermanentFlag = 0x4

// parseProcNetARP parses the Linux /proc/net/arp table. It keeps only completed
// entries, normalizes the MAC to lowercase colon form, drops broadcast/multicast
// pseudo-entries via the shared isRealNeighbor filter, and carries the device name.
// Malformed/short lines and the header are skipped. Pure (io.Reader in) so it is unit
// testable on any OS.
//
// Columns: IP address | HW type | Flags | HW address | Mask | Device
func parseProcNetARP(r io.Reader) ([]neighbor, error) {
	var out []neighbor
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue // header ("IP address ..."), blank, or short line
		}
		flags, err := strconv.ParseInt(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&linuxARPCompleteFlag == 0 {
			continue // header row's "Flags" column, or an incomplete (0x0) entry
		}
		hw, err := net.ParseMAC(f[3])
		if err != nil {
			continue
		}
		mac := strings.ToLower(hw.String())
		if !isRealNeighbor(f[0], mac) {
			continue
		}
		state := neighborStateDynamic
		if flags&linuxARPPermanentFlag != 0 {
			state = neighborStateStatic
		}
		out = append(out, neighbor{ip: f[0], mac: mac, iface: f[5], state: state})
	}
	return out, sc.Err()
}
