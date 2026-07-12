package dnscap

import "strings"

// dnsTypeName converts a numeric DNS QTYPE (as the Windows DNS-Client ETW event
// carries it, e.g. "1") to its mnemonic ("A"); unknown types pass through as
// "TYPE<n>". Shared (untagged) so it is unit-testable on any platform even though
// only the Windows capture backend uses it today.
func dnsTypeName(code string) string {
	switch strings.TrimSpace(code) {
	case "1":
		return "A"
	case "2":
		return "NS"
	case "5":
		return "CNAME"
	case "6":
		return "SOA"
	case "12":
		return "PTR"
	case "15":
		return "MX"
	case "16":
		return "TXT"
	case "28":
		return "AAAA"
	case "33":
		return "SRV"
	case "64":
		return "SVCB"
	case "65":
		return "HTTPS"
	case "255":
		return "ANY"
	case "":
		return ""
	default:
		return "TYPE" + strings.TrimSpace(code)
	}
}

// parseQueryResults extracts resolved answers from a DNS-Client 3008 QueryResults
// string. The provider formats it as ";"-separated entries, each roughly
// "type: <QTYPE> <data>" (A records may appear IPv4-mapped as "::ffff:1.2.3.4").
// We keep the value token of each entry and normalise the ::ffff: mapping.
func parseQueryResults(results string) []string {
	results = strings.TrimSpace(results)
	if results == "" {
		return nil
	}
	var out []string
	for _, entry := range strings.Split(results, ";") {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		val := strings.TrimPrefix(fields[len(fields)-1], "::ffff:")
		if val != "" {
			out = append(out, val)
		}
	}
	return out
}
