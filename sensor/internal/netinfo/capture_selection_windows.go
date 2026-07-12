//go:build windows

package netinfo

import "fmt"

// SelectCaptureInterface is unavailable on Windows: the base sensor captures DNS via
// the host-scoped ETW provider (not a pcap NIC) and discovers devices via native
// ICMP/ARP, so there is no capture interface to select. Stubbing it here keeps pcap
// (and its wpcap.dll runtime dependency) out of the Windows binary entirely.
func SelectCaptureInterface(opts CaptureSelectionOptions) (*CaptureSelection, error) {
	return nil, fmt.Errorf("capture-interface selection is not used on Windows (DNS is captured via ETW, host-scoped); --print-capture-plan is a Unix-only diagnostic")
}

// FormatCaptureSelection exists only so the shared --print-capture-plan path compiles
// on Windows; it is never reached because SelectCaptureInterface returns an error.
func FormatCaptureSelection(sel *CaptureSelection, purpose string) string {
	return "capture-interface selection is not applicable on Windows (ETW DNS capture is host-scoped)"
}
