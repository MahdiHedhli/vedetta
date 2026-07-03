package export

import "strings"

// Vendored Public Suffix List snapshot (alpha).
//
// This is a DELIBERATELY SMALL snapshot, not the full PSL. It covers the ICANN
// suffixes relevant to alpha testing plus multi-part suffixes exercised by the
// contract fixtures. Open question in spec.md: whether the full embedded PSL is
// required for GA — for alpha a vendored snapshot is accepted. Additions here
// are additive and safe.
//
// A "public suffix" is the part under which registrations are made. eTLD+1 is
// that suffix plus one label to its left (the registrable domain). All values
// are lowercase, no leading dot.

// multiPartSuffixes are suffixes with 2+ labels. Order does not matter; the
// reducer picks the LONGEST matching suffix.
var multiPartSuffixes = map[string]struct{}{
	"co.uk":         {},
	"org.uk":        {},
	"gov.uk":        {},
	"ac.uk":         {},
	"com.au":        {},
	"net.au":        {},
	"org.au":        {},
	"co.jp":         {},
	"co.nz":         {},
	"com.br":        {},
	"co.za":         {},
	"co.in":         {},
	"com.cn":        {},
	"pvt.k12.ma.us": {},
	// Reserved documentation TLD (RFC 2606) so fixtures reduce cleanly.
	"example": {},
}

// singleLabelTLDs is a small allowlist of single-label public suffixes we accept
// as real registrable TLDs for alpha. eTLD+1 under any of these is label+"."+tld.
var singleLabelTLDs = map[string]struct{}{
	"com": {}, "net": {}, "org": {}, "io": {}, "co": {}, "dev": {},
	"info": {}, "biz": {}, "app": {}, "xyz": {}, "us": {}, "uk": {},
	"de": {}, "fr": {}, "nl": {}, "ca": {}, "au": {}, "jp": {}, "cn": {},
	"br": {}, "in": {}, "za": {}, "nz": {}, "eu": {}, "me": {}, "tv": {},
	// RFC 2606 documentation TLDs.
	"example": {}, "test": {},
}

// eTLDPlusOne reduces a lowercase FQDN to its registrable domain (eTLD+1) using
// the vendored snapshot. It returns ("", false) when the input cannot be reduced
// (single-label, unknown suffix, or a bare public suffix with no registrable
// label). Callers treat !ok as "not exportable".
func eTLDPlusOne(fqdn string) (string, bool) {
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	if fqdn == "" {
		return "", false
	}
	labels := strings.Split(fqdn, ".")
	if len(labels) < 2 {
		return "", false // single-label
	}
	for _, l := range labels {
		if l == "" {
			return "", false // empty label (e.g. "a..b")
		}
	}

	// Try the longest multi-part suffix first (check 3-label then 2-label tails).
	for start := 0; start < len(labels)-1; start++ {
		candidate := strings.Join(labels[start:], ".")
		if _, ok := multiPartSuffixes[candidate]; ok {
			// suffix has (len(labels)-start) labels; need one more label to its left.
			if start == 0 {
				return "", false // input IS the bare suffix, no registrable label
			}
			return strings.Join(labels[start-1:], "."), true
		}
	}

	// Single-label TLD case.
	tld := labels[len(labels)-1]
	if _, ok := singleLabelTLDs[tld]; ok {
		return strings.Join(labels[len(labels)-2:], "."), true
	}

	return "", false
}
