package netscan

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// maxScanAddresses matches Core's upper bound for Unix Nmap targets. The native
// Windows sweep applies its tighter maxSweepHosts bound when it expands a range.
const maxScanAddresses = int64(1) << 24

// A numeric IPv4 expression never needs thousands of bytes unless it repeats
// or overlaps the same 0..255 values. Bounding the text itself prevents an
// attacker-controlled Core target from turning otherwise non-allocating parsing
// into an unbounded CPU exercise.
const maxNmapNumericTargetBytes = 4096

const nmapOctet = `(?:\d{1,3}(?:-\d{1,3})?)(?:,\d{1,3}(?:-\d{1,3})?)*`

// nmapRangeRe accepts Nmap's numeric IPv4 octet range/list syntax. Semantic
// validation below additionally enforces every numeric endpoint is 0..255.
var nmapRangeRe = regexp.MustCompile(`^` + nmapOctet + `\.` + nmapOctet + `\.` + nmapOctet + `\.` + nmapOctet + `$`)

// hostnameRe recognizes a strict hostname only so the validator can return a
// precise unsupported-target error. Active discovery is IPv4/no-DNS in this beta.
var hostnameRe = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

const shellMeta = ";|&$`<>()'\"\\"

// ValidateTarget is shared by both sensor backends and by startup preparation.
// Validating before enrollment prevents an invalid explicit --cidr from consuming
// a one-time code and installing a healthy-looking but scan-inert service.
func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("empty scan target")
	}
	if len(target) > maxNmapNumericTargetBytes {
		return fmt.Errorf("scan target is too long (maximum %d bytes)", maxNmapNumericTargetBytes)
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("scan target may not begin with '-': %q", target)
	}
	if strings.ContainsAny(target, " \t\r\n\f\v") {
		return fmt.Errorf("scan target may not contain whitespace: %q", target)
	}
	if strings.ContainsAny(target, shellMeta) {
		return fmt.Errorf("scan target contains forbidden metacharacter: %q", target)
	}
	if ip := net.ParseIP(target); ip != nil {
		if ip.To4() == nil || strings.Contains(target, ":") {
			return fmt.Errorf("active discovery is IPv4-only for this beta: %q", target)
		}
		return nil
	}
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		if ipnet.IP.To4() == nil || strings.Contains(target, ":") {
			return fmt.Errorf("active discovery is IPv4-only for this beta: %q", target)
		}
		ones, _ := ipnet.Mask.Size()
		if ones < 8 {
			return fmt.Errorf("scan target %q is too broad; use a specific subnet (minimum /8)", target)
		}
		return nil
	}
	if nmapRangeRe.MatchString(target) {
		if n := nmapRangeBreadth(target); n > maxScanAddresses {
			return fmt.Errorf("scan target %q spans too many addresses (> %d); narrow the range", target, maxScanAddresses)
		}
		return nil
	}
	if hostnameRe.MatchString(target) {
		return fmt.Errorf("hostname scan targets are unsupported in IPv4/no-DNS beta mode: %q", target)
	}
	return fmt.Errorf("scan target is not a supported IPv4, CIDR, or numeric range/list: %q", target)
}

func parseNmapOctetPart(part string) (int, int, error) {
	lo, hi := 0, 0
	if i := strings.IndexByte(part, '-'); i >= 0 {
		var err error
		lo, err = strconv.Atoi(part[:i])
		if err != nil {
			return 0, 0, err
		}
		hi, err = strconv.Atoi(part[i+1:])
		if err != nil {
			return 0, 0, err
		}
	} else {
		value, err := strconv.Atoi(part)
		if err != nil {
			return 0, 0, err
		}
		lo, hi = value, value
	}
	if lo < 0 || hi < lo || hi > 255 {
		return 0, 0, fmt.Errorf("IPv4 octet %q is outside 0..255", part)
	}
	return lo, hi, nil
}

// walkNmapOctet parses one comma-separated octet expression without first
// allocating a slice for every represented value. Returning false from visit
// stops the walk early; callers use that to cap cardinality and to answer
// membership queries in memory proportional to the input, not the range size.
func walkNmapOctet(raw string, visit func(lo, hi int) bool) error {
	for {
		part, rest, found := strings.Cut(raw, ",")
		lo, hi, err := parseNmapOctetPart(part)
		if err != nil {
			return err
		}
		if !visit(lo, hi) {
			return nil
		}
		if !found {
			return nil
		}
		raw = rest
	}
}

// nmapOctetCardinality counts represented values up to limit. A return value
// of limit+1 means the expression exceeded the cap; it is deliberately not an
// exact count because validation only needs to reject it.
func nmapOctetCardinality(raw string, limit int64) (int64, error) {
	if limit < 0 {
		return 0, fmt.Errorf("negative IPv4 octet cardinality limit")
	}
	var count int64
	err := walkNmapOctet(raw, func(lo, hi int) bool {
		width := int64(hi-lo) + 1
		if width > limit-count {
			count = limit + 1
			return false
		}
		count += width
		return true
	})
	return count, err
}

func expandNmapOctet(raw string, limit int64) ([]int, error) {
	count, err := nmapOctetCardinality(raw, limit)
	if err != nil {
		return nil, err
	}
	if count == 0 || count > limit {
		return nil, fmt.Errorf("IPv4 octet %q exceeds expansion limit %d", raw, limit)
	}
	values := make([]int, 0, int(count))
	err = walkNmapOctet(raw, func(lo, hi int) bool {
		for value := lo; value <= hi; value++ {
			values = append(values, value)
		}
		return true
	})
	return values, err
}

// nmapRangeBreadth returns the number of represented addresses. Any syntax or
// octet-bound anomaly returns a large sentinel so validation fails closed.
func nmapRangeBreadthLimit(target string, limit int64) int64 {
	if limit < 1 || len(target) > maxNmapNumericTargetBytes || !nmapRangeRe.MatchString(target) {
		return int64(1) << 62
	}
	total := int64(1)
	for _, octet := range strings.Split(target, ".") {
		// Count only as far as this octet can keep the Cartesian product
		// within the global limit. This prevents repeated 0-255 list entries
		// from allocating millions of ints before the breadth check runs.
		remaining := limit / total
		count, err := nmapOctetCardinality(octet, remaining)
		if err != nil || count == 0 {
			return int64(1) << 62
		}
		if count > remaining {
			return limit + 1
		}
		total *= count
	}
	return total
}

func nmapRangeBreadth(target string) int64 {
	return nmapRangeBreadthLimit(target, maxScanAddresses)
}

// targetContainsIPv4 checks membership without expanding a numeric Nmap target.
// Unix permits validated range/list targets larger than the native Windows sweep
// cap, so enumerating the Cartesian product here would either discard valid
// neighbor evidence or allocate an unnecessarily large slice.
func targetContainsIPv4(target, candidate string) bool {
	candidateIP := net.ParseIP(candidate)
	if candidateIP == nil || candidateIP.To4() == nil || strings.Contains(candidate, ":") {
		return false
	}
	candidateV4 := candidateIP.To4()
	if targetIP := net.ParseIP(target); targetIP != nil {
		return !strings.Contains(target, ":") && targetIP.To4() != nil && targetIP.To4().Equal(candidateV4)
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		return !strings.Contains(target, ":") && network.IP.To4() != nil && network.Contains(candidateV4)
	}
	if len(target) > maxNmapNumericTargetBytes || !nmapRangeRe.MatchString(target) || nmapRangeBreadth(target) > maxScanAddresses {
		return false
	}
	parts := strings.Split(target, ".")
	if len(parts) != net.IPv4len {
		return false
	}
	for i, part := range parts {
		matched := false
		err := walkNmapOctet(part, func(lo, hi int) bool {
			if int(candidateV4[i]) >= lo && int(candidateV4[i]) <= hi {
				matched = true
			}
			// Validate the entire expression even after a match. Otherwise a
			// prefix such as "2" could hide an invalid suffix such as "999".
			return true
		})
		if err != nil {
			return false
		}
		if !matched {
			return false
		}
	}
	return true
}

// enumerateNmapIPv4Target expands a bounded numeric range/list for the native
// Windows scanner. Unix hands the validated expression directly to Nmap.
func enumerateNmapIPv4Target(target string, limit int) ([]string, error) {
	breadth := nmapRangeBreadthLimit(target, int64(limit))
	if breadth <= 0 || breadth > int64(limit) {
		return nil, fmt.Errorf("numeric IPv4 target %q contains %d addresses; native sweep limit is %d", target, breadth, limit)
	}
	parts := strings.Split(target, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid numeric IPv4 target %q", target)
	}
	values := make([][]int, 4)
	for i := range parts {
		var err error
		values[i], err = expandNmapOctet(parts[i], int64(limit))
		if err != nil {
			return nil, fmt.Errorf("invalid numeric IPv4 target %q: %w", target, err)
		}
	}
	hosts := make([]string, 0, int(breadth))
	for _, a := range values[0] {
		for _, b := range values[1] {
			for _, c := range values[2] {
				for _, d := range values[3] {
					hosts = append(hosts, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
				}
			}
		}
	}
	return hosts, nil
}
