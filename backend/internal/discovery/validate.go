package discovery

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

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
	// CIDR (v4 or v6).
	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}
	// nmap IPv4 numeric range / octet list.
	if nmapRangeRe.MatchString(target) {
		return nil
	}
	// Strict DNS hostname.
	if len(target) <= 253 && dnsHostnameRe.MatchString(target) {
		return nil
	}

	return fmt.Errorf("scan target %q is not a valid IP, CIDR, nmap range, or hostname", target)
}
