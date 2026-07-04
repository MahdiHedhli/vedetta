package export

import (
	"net"
	"strings"
)

// Private/special-use suffixes that must never be exported (contract §5 rule 4,
// plan.md private-name filter).
var privateSuffixes = []string{
	".local", ".lan", ".home", ".internal", ".corp",
	"home.arpa", ".arpa", // covers in-addr.arpa / ip6.arpa reverse zones
}

// isPublicDomain reports whether a domain is safe to consider for export: a
// lowercased, multi-label, non-private, non-IP-literal FQDN that reduces under
// the vendored PSL. It is the single gate all domain material passes.
func isPublicDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return false
	}
	// URL syntax / whitespace / userinfo are forbidden entirely.
	if strings.ContainsAny(d, "/?#@ \t\r\n") {
		return false
	}
	// IP literal (v4 or v6) is not a domain.
	if net.ParseIP(d) != nil {
		return false
	}
	// Single label (no dot) is rejected.
	if !strings.Contains(d, ".") {
		return false
	}
	// Private / special-use suffixes.
	for _, suf := range privateSuffixes {
		if strings.HasSuffix(d, suf) {
			return false
		}
	}
	// Must reduce under the PSL to a registrable domain.
	if _, ok := eTLDPlusOne(d); !ok {
		return false
	}
	return true
}
