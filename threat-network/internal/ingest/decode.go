package ingest

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func intField(m map[string]json.RawMessage, key string, dst *int) error {
	rv, ok := m[key]
	if !ok {
		return errors.New(key + " required")
	}
	return json.Unmarshal(rv, dst)
}

func strField(m map[string]json.RawMessage, key string, dst *string) error {
	rv, ok := m[key]
	if !ok {
		return errors.New(key + " required")
	}
	return json.Unmarshal(rv, dst)
}

func timeField(m map[string]json.RawMessage, key string, dst *time.Time) error {
	var s string
	if err := strField(m, key, &s); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return errors.New("not RFC3339")
	}
	*dst = t.UTC()
	return nil
}

// decodeSignal validates and decodes a single signal. It returns (signal, false)
// on any per-signal STRUCTURAL failure (unknown kind, missing/invalid required
// field, confidence out of [0,1], observation_count out of [1,10000],
// distinct_asset_count out of [1,500], mis-aligned/out-of-window time_bucket,
// reason vocab violation, kind field-presence rule violations). These are
// non-fatal (rejected count), NOT whole-batch failures.
func decodeSignal(sr map[string]json.RawMessage, winStart, winEnd time.Time) (Signal, bool) {
	var s Signal

	if strField(sr, "signal_id", &s.SignalID) != nil || s.SignalID == "" {
		return s, false
	}
	if strField(sr, "kind", &s.Kind) != nil {
		return s, false
	}
	if s.Kind != KindKnownBad && s.Kind != KindCandidate && s.Kind != KindBehavior {
		return s, false // unknown kind → per-signal reject
	}

	// time_bucket: RFC3339, hour-aligned, within [window_start, window_end].
	var tb time.Time
	if timeField(sr, "time_bucket", &tb) != nil {
		return s, false
	}
	if tb.Minute() != 0 || tb.Second() != 0 || tb.Nanosecond() != 0 {
		return s, false // not hour-aligned
	}
	// bucket must be within the batch window [window_start, window_end)
	if tb.Before(winStart) || !tb.Before(winEnd) {
		return s, false
	}
	s.TimeBucket = tb

	// local_confidence ∈ [0,1]
	if rv, ok := sr["local_confidence"]; !ok || json.Unmarshal(rv, &s.LocalConfidence) != nil {
		return s, false
	}
	if s.LocalConfidence < 0 || s.LocalConfidence > 1 {
		return s, false
	}

	// local_reasons: 1..8 from vocabulary.
	if rv, ok := sr["local_reasons"]; !ok || json.Unmarshal(rv, &s.LocalReasons) != nil {
		return s, false
	}
	if len(s.LocalReasons) < 1 || len(s.LocalReasons) > 8 {
		return s, false
	}
	for _, r := range s.LocalReasons {
		if !reasonVocab[r] {
			return s, false
		}
	}

	// observation_count ∈ [1, 10000], distinct_asset_count ∈ [1, 500] (002 §4).
	// Both bounds are per-signal STRUCTURAL rejections (rejected count), not a
	// whole-batch 422.
	if rv, ok := sr["observation_count"]; !ok || json.Unmarshal(rv, &s.ObservationCount) != nil {
		return s, false
	}
	if s.ObservationCount < 1 || s.ObservationCount > 10000 {
		return s, false
	}
	if rv, ok := sr["distinct_asset_count"]; !ok || json.Unmarshal(rv, &s.DistinctAssetCount) != nil {
		return s, false
	}
	if s.DistinctAssetCount < 1 || s.DistinctAssetCount > 500 {
		return s, false
	}

	// Kind-specific fields + presence rules.
	switch s.Kind {
	case KindKnownBad:
		if strField(sr, "domain", &s.Domain) != nil || s.Domain == "" {
			return s, false
		}
		if strField(sr, "etld_plus_one", &s.EtldPlusOne) != nil || s.EtldPlusOne == "" {
			return s, false
		}
		if rv, ok := sr["blocked_count"]; ok {
			if json.Unmarshal(rv, &s.BlockedCount) != nil || s.BlockedCount < 0 || s.BlockedCount > s.ObservationCount {
				return s, false
			}
		}
		s.Domain = strings.ToLower(s.Domain)
		s.EtldPlusOne = strings.ToLower(s.EtldPlusOne)
		s.IndicatorKey = s.Domain
		s.Indicator = s.Domain
	case KindCandidate:
		// domain is FORBIDDEN on this kind (002 §4.2).
		if _, ok := sr["domain"]; ok {
			return s, false
		}
		if strField(sr, "etld_plus_one", &s.EtldPlusOne) != nil || s.EtldPlusOne == "" {
			return s, false
		}
		s.EtldPlusOne = strings.ToLower(s.EtldPlusOne)
		s.IndicatorKey = s.EtldPlusOne
		s.Indicator = s.EtldPlusOne
	case KindBehavior:
		// domain / etld_plus_one forbidden (002 §4.3).
		if _, ok := sr["domain"]; ok {
			return s, false
		}
		if _, ok := sr["etld_plus_one"]; ok {
			return s, false
		}
		if strField(sr, "behavior", &s.Behavior) != nil || !behaviorVocab[s.Behavior] {
			return s, false
		}
		s.IndicatorKey = s.Behavior
		s.Indicator = s.Behavior
	}
	return s, true
}
