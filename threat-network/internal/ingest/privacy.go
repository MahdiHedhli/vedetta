package ingest

import (
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Privacy re-gate: server-side defense-in-depth enforcement of the telemetry
// export contract §5 "forbidden content". Any violation rejects the WHOLE batch
// with 422 (per 002 §5), even though Core should never send such values.

// macRe matches MAC-address-shaped values (colon/hyphen/dot separated).
var macRe = regexp.MustCompile(`(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b([0-9a-f]{4}\.){2}[0-9a-f]{4}\b`)

// specialSuffixes are private/special-use zones that must never appear on the wire.
var specialSuffixes = []string{
	".local", ".lan", ".home", ".internal", ".corp",
	"home.arpa", ".arpa", "in-addr.arpa", "ip6.arpa",
}

// DNS name limits (RFC 1035 §2.3.4 / §3.1): a domain's presentation form is at
// most 253 characters and each label is 1..63 characters. Without these bounds a
// registered reporter can submit a megabyte-sized "domain" that is stored as a
// distinct indicator, exhausting storage (GHSA-7p69). A length violation is a
// per-item skip (see perItemSkipRules) — a malformed-but-not-poison value that
// must NOT dead-letter the rest of the batch, consistent with the PSL fix.
const (
	maxDNSNameLen  = 253
	maxDNSLabelLen = 63
)

// PrivacyViolation describes which rule tripped and where.
type PrivacyViolation struct {
	Rule   string // machine-readable rule name, e.g. "no_ip_literals"
	Detail string
}

// checkStringValue inspects a single string value drawn from a signal for
// IP-literal and MAC-shaped content (rules 2 & 3). It returns a violation or nil.
func checkStringValue(where, v string) *PrivacyViolation {
	if v == "" {
		return nil
	}
	if net.ParseIP(strings.TrimSpace(v)) != nil {
		return &PrivacyViolation{Rule: "no_ip_literals", Detail: where + ": string value is an IP literal"}
	}
	if macRe.MatchString(v) {
		return &PrivacyViolation{Rule: "no_mac_addresses", Detail: where + ": string value matches MAC pattern"}
	}
	return nil
}

// checkDNSLimits enforces DNS name/label length bounds on a domain-like value
// (already lower-cased/trimmed by the caller). It rejects an empty value, a
// total presentation length over 253, any empty label (e.g. "a..b" or a leading/
// trailing dot), and any label over 63 characters. The single "invalid_dns_name"
// rule is a per-item skip. This is the GHSA-7p69 resource-exhaustion guard.
func checkDNSLimits(where, v string) *PrivacyViolation {
	if v == "" {
		return &PrivacyViolation{Rule: "invalid_dns_name", Detail: where + ": empty domain name"}
	}
	// Tolerate a single fully-qualified trailing dot for the length accounting.
	name := strings.TrimSuffix(v, ".")
	if name == "" || len(name) > maxDNSNameLen {
		return &PrivacyViolation{Rule: "invalid_dns_name",
			Detail: where + ": domain name exceeds DNS length limit (253)"}
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return &PrivacyViolation{Rule: "invalid_dns_name", Detail: where + ": empty DNS label"}
		}
		if len(label) > maxDNSLabelLen {
			return &PrivacyViolation{Rule: "invalid_dns_name",
				Detail: where + ": DNS label exceeds 63 characters"}
		}
	}
	return nil
}

// checkDomainValue enforces rule 4 (and URL-syntax rule 7) on a domain-like value.
func checkDomainValue(where, raw string) *PrivacyViolation {
	if raw == "" {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(raw))

	// Rule 7: no URL syntax / whitespace / user parts.
	if strings.ContainsAny(v, "/?#@ \t\r\n") {
		return &PrivacyViolation{Rule: "no_url_syntax", Detail: where + ": value contains URL/host syntax"}
	}
	// DNS length bounds (GHSA-7p69): reject oversized names/labels before any
	// other classification so a megabyte-sized value is a per-item skip, not a
	// whole-batch reject (and can never reach storage as a distinct indicator).
	if lv := checkDNSLimits(where, v); lv != nil {
		return lv
	}
	// Rule 2/4: an IP literal is never a valid domain.
	if net.ParseIP(v) != nil {
		return &PrivacyViolation{Rule: "no_ip_literals", Detail: where + ": domain value is an IP literal"}
	}
	// Rule 4: special-use / private zones.
	for _, suf := range specialSuffixes {
		s := strings.TrimPrefix(suf, ".")
		if v == s || strings.HasSuffix(v, "."+s) || strings.HasSuffix(v, suf) {
			return &PrivacyViolation{Rule: "no_special_use_names", Detail: where + ": special-use/private zone " + suf}
		}
	}
	// Rule 4: single-label (no dot) is not a public registrable name.
	if !strings.Contains(v, ".") {
		return &PrivacyViolation{Rule: "no_single_label", Detail: where + ": single-label name not permitted"}
	}
	// Rule 4 (002 §5.4): the value MUST be reducible under the Public Suffix List.
	// A value that IS a public suffix (e.g. "co.uk") has no registrable eTLD+1 and
	// is rejected. This is the defense-in-depth PSL gate the withholding rules rely
	// on; without it, exact-host material could slip through the wire.
	if _, err := publicsuffix.EffectiveTLDPlusOne(v); err != nil {
		return &PrivacyViolation{Rule: "not_psl_reducible", Detail: where + ": value not reducible under the Public Suffix List"}
	}
	return nil
}

// checkCandidateEtld enforces the eTLD+1-ONLY withholding rule for
// high_confidence_domain_candidate signals (002 §4.2 / §5.4): the value carried
// MUST be its own eTLD+1 (no extra host labels). A value like
// "secret-victim-host.internal-corp-name.example" reduces to
// "internal-corp-name.example" and therefore leaks the exact host it came from —
// exactly what the withholding rule exists to prevent. Returns a violation or nil.
// Callers should run checkDomainValue first (single-label / special-use / IP /
// URL-syntax / PSL-reducibility); this adds the "value IS its own eTLD+1" gate.
func checkCandidateEtld(where, raw string) *PrivacyViolation {
	if raw == "" {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(raw))
	etld1, err := publicsuffix.EffectiveTLDPlusOne(v)
	if err != nil {
		// Not reducible (e.g. a bare public suffix). checkDomainValue also catches
		// this, but guard here so the function is safe standalone.
		return &PrivacyViolation{Rule: "not_psl_reducible", Detail: where + ": value not reducible under the Public Suffix List"}
	}
	if etld1 != v {
		return &PrivacyViolation{Rule: "candidate_not_etld_plus_one",
			Detail: where + ": high_confidence_domain_candidate must carry the eTLD+1 only (exact host withheld)"}
	}
	return nil
}

// checkKnownBadEtld verifies the etld_plus_one carried on a known_bad_domain_hit
// is the PSL reduction of the exact domain (002 §4.1 table: "PSL reduction of
// domain"). Returns a violation or nil.
func checkKnownBadEtld(where, domain, etld string) *PrivacyViolation {
	if domain == "" || etld == "" {
		return nil
	}
	d := strings.ToLower(strings.TrimSpace(domain))
	e := strings.ToLower(strings.TrimSpace(etld))
	reduced, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return &PrivacyViolation{Rule: "not_psl_reducible", Detail: where + ": domain not reducible under the Public Suffix List"}
	}
	if reduced != e {
		return &PrivacyViolation{Rule: "etld_plus_one_mismatch",
			Detail: where + ": etld_plus_one must be the PSL reduction of domain"}
	}
	return nil
}

// screenBatchRaw scans the raw decoded JSON for any forbidden content across all
// string values (defense in depth, catches identifier-like strings anywhere).
// It complements the typed per-field checks. Returns the first violation found.
func screenRawStrings(where string, node interface{}) *PrivacyViolation {
	switch t := node.(type) {
	case string:
		return checkStringValue(where, t)
	case []interface{}:
		for i, e := range t {
			if v := screenRawStrings(where, e); v != nil {
				return v
			}
			_ = i
		}
	case map[string]interface{}:
		for k, e := range t {
			if v := screenRawStrings(where+"."+k, e); v != nil {
				return v
			}
		}
	}
	return nil
}
