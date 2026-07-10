package discovery

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// maxScanAddresses bounds how many addresses a single scan target may span. It is
// aligned with the CIDR floor below (/8 for IPv4 = 2^24), so an nmap octet-range
// target cannot express a broader scan than a CIDR is allowed to (GHSA-c5gj).
const maxScanAddresses = int64(1) << 24

// forbiddenTargetChars are shell metacharacters and redirection operators that must
// never appear in a scan target. Even though we always exec nmap directly (never a
// shell) and pass "--" before target operands, rejecting these keeps the input to a
// well-understood shape and blocks nmap-option / argument injection (GHSA-c5gj).
const forbiddenTargetChars = ";|&$`<>()'\""

var (
	// dnsHostnameRe matches a strict RFC 1123 DNS hostname: dot-separated labels of
	// letters/digits/hyphen, no label starting or ending with a hyphen, each <= 63.
	dnsHostnameRe = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

	// nmapRangeRe matches nmap IPv4 octet-range / octet-list syntax such as
	// "10.0.0.1-50", "192.168.1.1-254", and comma lists like "10.0.0.1,2,3". Each of
	// the four octets is a number, a low-high range, or a comma-separated list of
	// those. Value bounds (0-255) are not enforced here — nmap rejects out-of-range
	// octets itself; our job is to guarantee the string is injection-safe.
	nmapRangeRe = regexp.MustCompile(`^` + nmapOctet + `\.` + nmapOctet + `\.` + nmapOctet + `\.` + nmapOctet + `$`)
)

const nmapOctet = `(?:\d{1,3}(?:-\d{1,3})?)(?:,\d{1,3}(?:-\d{1,3})?)*`

// ValidateScanTarget reports whether target is safe to hand to nmap as a scan
// operand. A target is valid ONLY if it is a bare IP, a CIDR, an nmap numeric range
// (e.g. 10.0.0.1-50, optionally with comma octet-lists), or a strict DNS hostname —
// and never if it begins with "-", contains whitespace, or contains a shell
// metacharacter. These rules are intentionally duplicated in the sensor module,
// which cannot share this import.
func ValidateScanTarget(target string) error {
	if target == "" {
		return fmt.Errorf("scan target is empty")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("scan target %q must not begin with '-'", target)
	}
	if strings.ContainsAny(target, " \t\r\n\v\f") {
		return fmt.Errorf("scan target must not contain whitespace")
	}
	if strings.ContainsAny(target, forbiddenTargetChars) {
		return fmt.Errorf("scan target contains a forbidden character")
	}

	// Bare IP (v4 or v6).
	if net.ParseIP(target) != nil {
		return nil
	}
	// CIDR (v4 or v6) — but reject absurdly broad ranges a LAN scanner should never
	// receive (e.g. 0.0.0.0/0). A forged/over-broad target would otherwise make the
	// root-running sensor scan far beyond the local network (GHSA-c5gj).
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		ones, _ := ipnet.Mask.Size()
		minOnes := 8
		if ipnet.IP.To4() == nil {
			minOnes = 32 // IPv6
		}
		if ones < minOnes {
			return fmt.Errorf("scan target %q is too broad; use a specific subnet (minimum /%d)", target, minOnes)
		}
		return nil
	}
	// nmap IPv4 numeric range / octet list — but bound its breadth the same way the
	// CIDR floor does, so a range like 0-255.0-255.0-255.0-255 cannot slip a whole-
	// internet scan past the /8 check to the root sensor (GHSA-c5gj).
	if nmapRangeRe.MatchString(target) {
		if n := nmapRangeBreadth(target); n > maxScanAddresses {
			return fmt.Errorf("scan target %q spans too many addresses (> %d); narrow the range", target, maxScanAddresses)
		}
		return nil
	}
	// Strict DNS hostname.
	if len(target) <= 253 && dnsHostnameRe.MatchString(target) {
		return nil
	}

	return fmt.Errorf("scan target %q is not a valid IP, CIDR, nmap range, or hostname", target)
}

// nmapRangeBreadth returns how many addresses an nmap octet-range/list target
// spans (target must already match nmapRangeRe). It returns a large sentinel on
// any parse anomaly or once the running product exceeds the cap, so an over-broad
// or malformed range fails closed.
func nmapRangeBreadth(target string) int64 {
	octets := strings.Split(target, ".")
	if len(octets) != 4 {
		return int64(1) << 62
	}
	total := int64(1)
	for _, oct := range octets {
		var cnt int64
		for _, part := range strings.Split(oct, ",") {
			if i := strings.IndexByte(part, '-'); i >= 0 {
				lo, err1 := strconv.Atoi(part[:i])
				hi, err2 := strconv.Atoi(part[i+1:])
				if err1 != nil || err2 != nil || hi < lo {
					return int64(1) << 62
				}
				cnt += int64(hi-lo) + 1
			} else {
				cnt++
			}
		}
		total *= cnt
		if total > maxScanAddresses {
			return total
		}
	}
	return total
}
