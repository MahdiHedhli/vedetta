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
	// dnsHostnameRe recognizes values that are syntactically hostnames so the beta
	// API can return a precise unsupported-target error instead of a generic parse
	// failure. Active scanning is currently IPv4/no-DNS only.
	dnsHostnameRe = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

	// nmapRangeRe matches nmap IPv4 octet-range / octet-list syntax such as
	// "10.0.0.1-50", "192.168.1.1-254", and comma lists like "10.0.0.1,2,3". Each of
	// the four octets is a number, a low-high range, or a comma-separated list of
	// those. nmapRangeBreadth performs the semantic 0..255 and ordering checks; the
	// regex first guarantees the operand is injection-safe.
	nmapRangeRe = regexp.MustCompile(`^` + nmapOctet + `\.` + nmapOctet + `\.` + nmapOctet + `\.` + nmapOctet + `$`)
)

const nmapOctet = `(?:\d{1,3}(?:-\d{1,3})?)(?:,\d{1,3}(?:-\d{1,3})?)*`

// ValidateScanTarget reports whether target is safe to hand to nmap as a scan
// operand. A target is valid ONLY if it is a bare IPv4, an IPv4 CIDR, or an nmap
// numeric IPv4 range/list (e.g. 10.0.0.1-50 or 10.0.0.1,2,3), and never if it
// begins with "-", contains whitespace, or contains a shell metacharacter. IPv6
// and hostname scanning are rejected until the sensor can actually execute them
// without false-empty results. These rules are intentionally duplicated in the
// sensor module, which cannot share this import.
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

	// Bare IPv4. Reject IPv4-mapped IPv6 spellings: the sensor passes the original
	// colon-form operand to Nmap, which can skip it while exiting successfully.
	if ip := net.ParseIP(target); ip != nil {
		if ip.To4() == nil || strings.Contains(target, ":") {
			return fmt.Errorf("scan target %q is unsupported; active scanning is IPv4-only in this beta", target)
		}
		return nil
	}
	// IPv4 CIDR — reject unsupported families and absurdly broad ranges a LAN scanner should never
	// receive (e.g. 0.0.0.0/0). A forged/over-broad target would otherwise make the
	// root-running sensor scan far beyond the local network (GHSA-c5gj).
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		if ipnet.IP.To4() == nil || strings.Contains(target, ":") {
			return fmt.Errorf("scan target %q is unsupported; active scanning is IPv4-only in this beta", target)
		}
		ones, _ := ipnet.Mask.Size()
		if ones < 8 {
			return fmt.Errorf("scan target %q is too broad; use a specific subnet (minimum /8)", target)
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
		return fmt.Errorf("scan target %q is unsupported; hostname scanning is disabled in IPv4/no-DNS beta mode", target)
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
			lo, hi := 0, 0
			if i := strings.IndexByte(part, '-'); i >= 0 {
				var err1, err2 error
				lo, err1 = strconv.Atoi(part[:i])
				hi, err2 = strconv.Atoi(part[i+1:])
				if err1 != nil || err2 != nil {
					return int64(1) << 62
				}
			} else {
				value, err := strconv.Atoi(part)
				if err != nil {
					return int64(1) << 62
				}
				lo, hi = value, value
			}
			if lo < 0 || hi < lo || hi > 255 {
				return int64(1) << 62
			}
			cnt += int64(hi-lo) + 1
		}
		total *= cnt
		if total > maxScanAddresses {
			return total
		}
	}
	return total
}
