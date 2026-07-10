package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/valid"
)

// Signal kinds (002 contract §4).
const (
	KindKnownBad  = "known_bad_domain_hit"
	KindCandidate = "high_confidence_domain_candidate"
	KindBehavior  = "behavior_summary"
)

// allowedTopKeys are the ONLY permitted batch envelope keys (002 §3).
var allowedTopKeys = map[string]bool{
	"schema_version": true, "batch_id": true, "generated_at": true,
	"window_start": true, "window_end": true, "signals": true,
}

// allowedCommonSignalKeys are permitted on every signal (002 §4).
var allowedCommonSignalKeys = map[string]bool{
	"signal_id": true, "kind": true, "time_bucket": true, "local_confidence": true,
	"local_reasons": true, "observation_count": true, "distinct_asset_count": true,
}

// allowedKindKeys lists the extra keys permitted per kind (002 §4.1-4.3).
var allowedKindKeys = map[string]map[string]bool{
	KindKnownBad:  {"domain": true, "etld_plus_one": true, "blocked_count": true},
	KindCandidate: {"etld_plus_one": true},
	KindBehavior:  {"behavior": true},
}

// reasonVocab is the schema_version 1 reason vocabulary (002 §6).
var reasonVocab = map[string]bool{
	"known_bad": true, "c2_candidate": true, "dga_candidate": true,
	"tunneling_candidate": true, "beaconing_candidate": true, "newly_registered": true,
	"dns_rebinding_candidate": true, "public_resolver_bypass": true,
	"threat_feed_match": true, "high_entropy": true,
}

// behaviorVocab is the permitted behavior enum (002 §4.3).
var behaviorVocab = map[string]bool{
	"dns_beaconing_candidate": true, "dga_burst_candidate": true,
	"dns_tunneling_candidate": true, "new_domain_volume_anomaly": true,
}

const maxBatchItems = 250

// Batch is the decoded, structurally-typed telemetry batch envelope.
type Batch struct {
	SchemaVersion int
	BatchID       string
	GeneratedAt   time.Time
	WindowStart   time.Time
	WindowEnd     time.Time
	Signals       []Signal
}

// Signal is one decoded, structurally-typed signal record.
type Signal struct {
	SignalID           string
	Kind               string
	TimeBucket         time.Time
	LocalConfidence    float64
	LocalReasons       []string
	ObservationCount   int
	DistinctAssetCount int
	// kind-specific
	Domain       string
	EtldPlusOne  string
	Behavior     string
	BlockedCount int
	// derived
	IndicatorKey string
	Indicator    string
}

// StrictError is a whole-batch rejection: unknown key (schema tripwire) or a
// privacy-gate violation. It maps to 422 with body {error, rule, detail, batch_id}.
type StrictError struct {
	ErrorName string // "strict_schema" | "forbidden_content"
	Rule      string
	Detail    string
}

func (e *StrictError) Error() string { return e.ErrorName + "/" + e.Rule + ": " + e.Detail }

// EnvelopeError is a whole-batch 400 for envelope/schema-version failures that
// are NOT the strict/privacy tripwire (e.g. bad schema_version, malformed JSON).
type EnvelopeError struct {
	Code   string
	Detail string
}

func (e *EnvelopeError) Error() string { return e.Code + ": " + e.Detail }

// ParseAndValidate decodes and validates a batch body. It enforces:
//   - strict-schema unknown-key detection (whole-batch StrictError, →422)
//   - privacy re-gate (whole-batch StrictError, →422)
//   - envelope structural rules (EnvelopeError, →400)
//
// Per-signal STRUCTURAL invalidity is NOT fatal: such signals are dropped and
// their count returned in rejected. It returns the valid signals and the
// rejected count.
func ParseAndValidate(body []byte) (*Batch, int, error) {
	// First decode into a generic tree to enforce strict keys and run the raw
	// privacy string screen (defense in depth against identifier-like values).
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&raw); err != nil {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "batch body is not a JSON object"}
	}
	// Strict single-object decode (GHSA-hx86): a well-formed first object must be
	// the ENTIRE body. Trailing objects/tokens (e.g. JSON smuggling past the first
	// value) reject the whole batch rather than being silently ignored.
	if dec.More() {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "trailing data after batch object"}
	}

	// Strict top-level keys (002 §3/§5 rule 1) — the poisoning/privacy tripwire.
	for k := range raw {
		if !allowedTopKeys[k] {
			return nil, 0, &StrictError{ErrorName: "strict_schema", Rule: "unknown_key",
				Detail: "unknown top-level key " + k}
		}
	}

	b := &Batch{}
	if err := intField(raw, "schema_version", &b.SchemaVersion); err != nil {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: err.Error()}
	}
	if b.SchemaVersion != 1 {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA",
			Detail: fmt.Sprintf("unsupported schema_version %d", b.SchemaVersion)}
	}
	if err := strField(raw, "batch_id", &b.BatchID); err != nil || b.BatchID == "" {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "batch_id required"}
	}
	// Wire-format validation (GHSA-hx86): batch_id must be a UUIDv4.
	if !valid.UUIDv4(b.BatchID) {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "batch_id must be a UUIDv4"}
	}
	if err := timeField(raw, "generated_at", &b.GeneratedAt); err != nil {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "generated_at: " + err.Error()}
	}
	if err := timeField(raw, "window_start", &b.WindowStart); err != nil {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "window_start: " + err.Error()}
	}
	if err := timeField(raw, "window_end", &b.WindowEnd); err != nil {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "window_end: " + err.Error()}
	}
	if !b.WindowEnd.After(b.WindowStart) {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "window_end must be after window_start"}
	}

	sigsRaw, ok := raw["signals"]
	if !ok {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "signals required"}
	}
	var sigList []map[string]json.RawMessage
	if err := json.Unmarshal(sigsRaw, &sigList); err != nil {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "signals must be an array of objects"}
	}
	if len(sigList) < 1 {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA", Detail: "signals must contain 1..250 items"}
	}
	if len(sigList) > maxBatchItems {
		return nil, 0, &EnvelopeError{Code: "INVALID_SCHEMA",
			Detail: fmt.Sprintf("signals exceeds max %d", maxBatchItems)}
	}

	rejected := 0
	for i, sr := range sigList {
		// Strict per-signal key check + privacy gate are WHOLE-BATCH fatal.
		if serr := strictSignalKeys(i, sr); serr != nil {
			return nil, 0, serr
		}
		if perr := privacyScreenSignal(i, sr); perr != nil {
			return nil, 0, &StrictError{ErrorName: "forbidden_content", Rule: perr.Rule, Detail: perr.Detail}
		}

		sig, structuralOK := decodeSignal(sr, b.WindowStart, b.WindowEnd)
		if !structuralOK {
			// Per-signal structural invalidity → counted in rejected only.
			rejected++
			continue
		}
		b.Signals = append(b.Signals, sig)
	}
	return b, rejected, nil
}

// strictSignalKeys enforces the strict-schema tripwire per signal: unknown keys
// (common or for the signal's kind) reject the whole batch. Unknown KIND values
// are handled as per-signal structural rejection in decodeSignal, not here.
func strictSignalKeys(idx int, sr map[string]json.RawMessage) *StrictError {
	// Determine kind for kind-specific key allowance; unknown kinds are handled
	// downstream (per-signal reject), so here we only allow keys valid for a
	// KNOWN kind. If kind is unknown/missing, any non-common key is "unknown".
	var kind string
	if kr, ok := sr["kind"]; ok {
		_ = json.Unmarshal(kr, &kind)
	}
	kindKeys := allowedKindKeys[kind]
	for k := range sr {
		if allowedCommonSignalKeys[k] {
			continue
		}
		if kindKeys != nil && kindKeys[k] {
			continue
		}
		return &StrictError{ErrorName: "strict_schema", Rule: "unknown_key",
			Detail: fmt.Sprintf("signal %d: unknown key %q", idx+1, k)}
	}
	return nil
}

// privacyScreenSignal runs the privacy re-gate over a signal's fields.
func privacyScreenSignal(idx int, sr map[string]json.RawMessage) *PrivacyViolation {
	where := fmt.Sprintf("signal %d", idx+1)

	// Determine kind for kind-specific withholding enforcement (002 §4.1-4.2).
	var kind string
	if kr, ok := sr["kind"]; ok {
		_ = json.Unmarshal(kr, &kind)
	}

	// Domain-like fields get the strict domain check (single-label, special-use,
	// IP literal, URL syntax, AND PSL-reducibility per §5.4).
	var domainVal, etldVal string
	for _, key := range []string{"domain", "etld_plus_one"} {
		if rv, ok := sr[key]; ok {
			var s string
			if json.Unmarshal(rv, &s) == nil {
				if key == "domain" {
					domainVal = s
				} else {
					etldVal = s
				}
				if v := checkDomainValue(where+"."+key, s); v != nil {
					return v
				}
			}
		}
	}

	// Kind-specific withholding enforcement (002 §4.1-4.2 / §5.4):
	switch kind {
	case KindCandidate:
		// etld_plus_one MUST be its own eTLD+1 (exact host withheld). A full
		// subdomain in this field leaks the exact host — reject the whole batch.
		if v := checkCandidateEtld(where+".etld_plus_one", etldVal); v != nil {
			return v
		}
	case KindKnownBad:
		// etld_plus_one MUST be the PSL reduction of the exact domain.
		if v := checkKnownBadEtld(where, domainVal, etldVal); v != nil {
			return v
		}
	}
	// Every string value anywhere gets the IP/MAC screen (catches stray literals).
	var generic map[string]interface{}
	blob, _ := json.Marshal(sr)
	if json.Unmarshal(blob, &generic) == nil {
		if v := screenRawStrings(where, generic); v != nil {
			return v
		}
	}
	return nil
}
