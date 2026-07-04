package export

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// LeakScan is the privacy regression gate. Given serialized batch bytes it
// returns every violation of the wire contract's forbidden-content rules (§5).
// An empty slice means clean. It is used across the test suite (and could be
// wired as a belt-and-suspenders check before egress).
//
// It is intentionally strict and self-contained (stdlib only) so it can run in
// CI as part of `go test ./...`.

// contractTopLevelKeys and contractSignalKeys are the ONLY JSON keys permitted
// at each position (contract §3/§4). Any other key is a violation.
var contractTopLevelKeys = map[string]bool{
	"schema_version": true, "batch_id": true, "generated_at": true,
	"window_start": true, "window_end": true, "signals": true,
}

var contractSignalKeys = map[string]bool{
	"signal_id": true, "kind": true, "time_bucket": true,
	"domain": true, "etld_plus_one": true, "behavior": true,
	"local_confidence": true, "local_reasons": true,
	"observation_count": true, "distinct_asset_count": true,
	"blocked_count": true,
}

var (
	// IPv4 literal anywhere (covers RFC1918, loopback, link-local, public).
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// IPv6 literal (needs at least one "::" or several ":" groups of hex).
	reIPv6 = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b|::[0-9a-fA-F]`)
	// MAC address shaped values (colon or dash separated).
	reMAC = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b`)
)

var forbiddenSuffixes = []string{".local", ".lan", ".home", ".internal", ".corp", "home.arpa", ".arpa"}

// LeakScan returns a list of human-readable violation descriptions.
func LeakScan(batchJSON []byte) []string {
	var violations []string

	// Structural: unknown keys.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(batchJSON, &top); err != nil {
		return []string{fmt.Sprintf("batch not valid JSON object: %v", err)}
	}
	for k := range top {
		if !contractTopLevelKeys[k] {
			violations = append(violations, "forbidden top-level key: "+k)
		}
	}
	if raw, ok := top["signals"]; ok {
		var sigs []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &sigs); err == nil {
			for i, sig := range sigs {
				for k := range sig {
					if !contractSignalKeys[k] {
						violations = append(violations, fmt.Sprintf("signal %d: forbidden key %q", i, k))
					}
				}
				if raw, ok := sig["local_reasons"]; ok {
					var reasons []string
					if json.Unmarshal(raw, &reasons) == nil {
						for _, r := range reasons {
							if _, valid := reasonVocab[r]; !valid {
								violations = append(violations, fmt.Sprintf("signal %d: non-vocabulary reason %q", i, r))
							}
						}
					}
				}
			}
		}
	}

	// Value scan over every string in the JSON tree.
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case string:
			violations = append(violations, scanString(path, t)...)
		case map[string]any:
			for k, vv := range t {
				walk(path+"."+k, vv)
			}
		case []any:
			for i, vv := range t {
				walk(fmt.Sprintf("%s[%d]", path, i), vv)
			}
		}
	}
	var tree any
	if json.Unmarshal(batchJSON, &tree) == nil {
		walk("$", tree)
	}

	return violations
}

func scanString(path, s string) []string {
	var out []string
	if reIPv4.MatchString(s) {
		out = append(out, path+": IPv4 literal in string value")
	}
	if reIPv6.MatchString(s) {
		out = append(out, path+": IPv6 literal in string value")
	}
	if reMAC.MatchString(s) {
		out = append(out, path+": MAC-shaped value in string")
	}
	if strings.ContainsAny(s, "/?#@") {
		out = append(out, path+": URL syntax / userinfo in string value")
	}
	low := strings.ToLower(strings.TrimSuffix(s, "."))
	for _, suf := range forbiddenSuffixes {
		if strings.HasSuffix(low, suf) {
			out = append(out, path+": forbidden private suffix "+suf)
		}
	}
	return out
}
