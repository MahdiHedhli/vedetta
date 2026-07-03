package ingest

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// validBatch returns a well-formed batch body with one signal per kind, matching
// the 002 contract synthetic example.
func validBatch(batchID string) []byte {
	return []byte(fmt.Sprintf(`{
      "schema_version": 1,
      "batch_id": %q,
      "generated_at": "2026-07-03T14:15:02Z",
      "window_start": "2026-07-03T14:00:00Z",
      "window_end": "2026-07-03T15:00:00Z",
      "signals": [
        {"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
         "domain":"c2-payload.badzone.example","etld_plus_one":"badzone.example",
         "local_confidence":0.99,"local_reasons":["known_bad","threat_feed_match"],
         "observation_count":4,"distinct_asset_count":2,"blocked_count":4},
        {"signal_id":"s2","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
         "etld_plus_one":"qxv-rotator.example","local_confidence":0.91,
         "local_reasons":["dga_candidate","newly_registered"],
         "observation_count":17,"distinct_asset_count":1},
        {"signal_id":"s3","kind":"behavior_summary","time_bucket":"2026-07-03T14:00:00Z",
         "behavior":"dns_beaconing_candidate","local_confidence":0.81,
         "local_reasons":["beaconing_candidate"],"observation_count":6,"distinct_asset_count":2}
      ]
    }`, batchID))
}

func TestParseValidBatch(t *testing.T) {
	b, rejected, err := ParseAndValidate(validBatch("b1"))
	if err != nil {
		t.Fatalf("expected valid batch, got %v", err)
	}
	if rejected != 0 {
		t.Fatalf("expected 0 rejected, got %d", rejected)
	}
	if len(b.Signals) != 3 {
		t.Fatalf("expected 3 signals, got %d", len(b.Signals))
	}
}

func TestUnknownTopLevelKeyRejectsWholeBatch(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[],"evil_key":"x"}`)
	_, _, err := ParseAndValidate(body)
	se, ok := err.(*StrictError)
	if !ok {
		t.Fatalf("expected *StrictError, got %T (%v)", err, err)
	}
	if se.ErrorName != "strict_schema" || se.Rule != "unknown_key" {
		t.Fatalf("unexpected strict error: %+v", se)
	}
}

func TestUnknownSignalKeyRejectsWholeBatch(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"behavior_summary","time_bucket":"2026-07-03T14:00:00Z",
        "behavior":"dns_beaconing_candidate","local_confidence":0.8,"local_reasons":["beaconing_candidate"],
        "observation_count":1,"distinct_asset_count":1,"source_hash":"deadbeef"}]}`)
	_, _, err := ParseAndValidate(body)
	se, ok := err.(*StrictError)
	if !ok {
		t.Fatalf("expected *StrictError, got %T (%v)", err, err)
	}
	if se.Rule != "unknown_key" {
		t.Fatalf("expected unknown_key, got %s", se.Rule)
	}
}

// TestPrivacyReGateWholeBatch422 covers every forbidden class from 002 §5.
func TestPrivacyReGateWholeBatch422(t *testing.T) {
	base := func(field, kind, value string) []byte {
		var sig string
		switch kind {
		case KindKnownBad:
			sig = fmt.Sprintf(`{"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
              "domain":%q,"etld_plus_one":"badzone.example","local_confidence":0.9,
              "local_reasons":["known_bad"],"observation_count":1,"distinct_asset_count":1}`, value)
		case KindCandidate:
			sig = fmt.Sprintf(`{"signal_id":"s1","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
              "etld_plus_one":%q,"local_confidence":0.9,"local_reasons":["dga_candidate"],
              "observation_count":1,"distinct_asset_count":1}`, value)
		}
		_ = field
		return []byte(fmt.Sprintf(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
          "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[%s]}`, sig))
	}

	cases := []struct {
		name  string
		kind  string
		value string
	}{
		{"dot_local", KindKnownBad, "printer.local"},
		{"dot_lan", KindKnownBad, "nas.lan"},
		{"dot_home", KindCandidate, "device.home"},
		{"dot_internal", KindCandidate, "svc.internal"},
		{"dot_corp", KindCandidate, "app.corp"},
		{"home_arpa", KindKnownBad, "host.home.arpa"},
		{"in_addr_arpa", KindKnownBad, "1.2.0.192.in-addr.arpa"},
		{"ip6_arpa", KindKnownBad, "x.ip6.arpa"},
		{"single_label", KindCandidate, "localhost"},
		{"ip_literal_v4", KindCandidate, "192.0.2.7"},
		{"ip_literal_v6", KindCandidate, "2001:db8::1"},
		{"url_syntax", KindKnownBad, "bad.example/evil"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := ParseAndValidate(base("domain", c.kind, c.value))
			se, ok := err.(*StrictError)
			if !ok {
				t.Fatalf("expected *StrictError (422), got %T (%v)", err, err)
			}
			if se.ErrorName != "forbidden_content" {
				t.Fatalf("expected forbidden_content, got %s (rule=%s)", se.ErrorName, se.Rule)
			}
		})
	}
}

func TestMacLiteralAnywhereRejected(t *testing.T) {
	// A MAC-shaped value smuggled into a reason-adjacent string is caught by the
	// generic raw-string screen. Here we place it in etld_plus_one.
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
        "etld_plus_one":"00:00:5e:00:53:2a","local_confidence":0.9,"local_reasons":["dga_candidate"],
        "observation_count":1,"distinct_asset_count":1}]}`)
	_, _, err := ParseAndValidate(body)
	if _, ok := err.(*StrictError); !ok {
		t.Fatalf("expected StrictError for MAC-shaped value, got %T (%v)", err, err)
	}
}

func TestValidSubdomainAccepted(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
        "domain":"sub.badhost.example","etld_plus_one":"badhost.example","local_confidence":0.9,
        "local_reasons":["known_bad"],"observation_count":1,"distinct_asset_count":1}]}`)
	_, rejected, err := ParseAndValidate(body)
	if err != nil {
		t.Fatalf("expected sub.badhost.example accepted, got %v", err)
	}
	if rejected != 0 {
		t.Fatalf("expected 0 rejected, got %d", rejected)
	}
}

// TestCandidateFullSubdomainRejected is the finding #2 regression: a
// high_confidence_domain_candidate whose etld_plus_one field carries a full
// subdomain (exact host NOT withheld) must reject the whole batch under the PSL
// re-gate. Previously this leaked the exact host verbatim into the feed.
func TestCandidateFullSubdomainRejected(t *testing.T) {
	cases := []string{
		"secret-victim-host.internal-corp-name.example",
		"host.badzone.example",
		"a.b.badzone.example",
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
              "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
              "signals":[{"signal_id":"s1","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
                "etld_plus_one":%q,"local_confidence":0.9,"local_reasons":["dga_candidate"],
                "observation_count":1,"distinct_asset_count":1}]}`, v))
			_, _, err := ParseAndValidate(body)
			se, ok := err.(*StrictError)
			if !ok {
				t.Fatalf("expected *StrictError (422), got %T (%v)", err, err)
			}
			if se.ErrorName != "forbidden_content" || se.Rule != "candidate_not_etld_plus_one" {
				t.Fatalf("expected forbidden_content/candidate_not_etld_plus_one, got %s/%s", se.ErrorName, se.Rule)
			}
		})
	}
}

// TestCandidateExactEtldAccepted verifies a candidate carrying its own eTLD+1 is
// accepted (the withholding rule permits eTLD+1 only, and this IS the eTLD+1).
func TestCandidateExactEtldAccepted(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
        "etld_plus_one":"qxv-rotator.example","local_confidence":0.9,"local_reasons":["dga_candidate"],
        "observation_count":1,"distinct_asset_count":1}]}`)
	if _, rejected, err := ParseAndValidate(body); err != nil || rejected != 0 {
		t.Fatalf("expected qxv-rotator.example accepted, got rejected=%d err=%v", rejected, err)
	}
}

// TestNonPSLReducibleRejected covers §5.4: a value that is a bare public suffix
// (no registrable eTLD+1) is not reducible under the PSL and rejects the batch.
func TestNonPSLReducibleRejected(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
        "etld_plus_one":"co.uk","local_confidence":0.9,"local_reasons":["dga_candidate"],
        "observation_count":1,"distinct_asset_count":1}]}`)
	_, _, err := ParseAndValidate(body)
	se, ok := err.(*StrictError)
	if !ok {
		t.Fatalf("expected *StrictError for non-PSL-reducible value, got %T (%v)", err, err)
	}
	if se.ErrorName != "forbidden_content" || se.Rule != "not_psl_reducible" {
		t.Fatalf("expected forbidden_content/not_psl_reducible, got %s/%s", se.ErrorName, se.Rule)
	}
}

// TestKnownBadEtldMismatchRejected covers §4.1: etld_plus_one must be the PSL
// reduction of the exact domain; a mismatched eTLD+1 rejects the batch.
func TestKnownBadEtldMismatchRejected(t *testing.T) {
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
        "domain":"c2.badzone.example","etld_plus_one":"otherzone.example","local_confidence":0.9,
        "local_reasons":["known_bad"],"observation_count":1,"distinct_asset_count":1}]}`)
	_, _, err := ParseAndValidate(body)
	se, ok := err.(*StrictError)
	if !ok {
		t.Fatalf("expected *StrictError for etld mismatch, got %T (%v)", err, err)
	}
	if se.ErrorName != "forbidden_content" || se.Rule != "etld_plus_one_mismatch" {
		t.Fatalf("expected forbidden_content/etld_plus_one_mismatch, got %s/%s", se.ErrorName, se.Rule)
	}
}

func TestPerSignalStructuralRejection(t *testing.T) {
	// One valid + several structurally invalid signals → rejected count reflects
	// them, batch is NOT wholesale failed.
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[
        {"signal_id":"ok","kind":"behavior_summary","time_bucket":"2026-07-03T14:00:00Z",
         "behavior":"dns_beaconing_candidate","local_confidence":0.8,"local_reasons":["beaconing_candidate"],
         "observation_count":1,"distinct_asset_count":1},
        {"signal_id":"badconf","kind":"behavior_summary","time_bucket":"2026-07-03T14:00:00Z",
         "behavior":"dns_beaconing_candidate","local_confidence":1.5,"local_reasons":["beaconing_candidate"],
         "observation_count":1,"distinct_asset_count":1},
        {"signal_id":"unknownkind","kind":"totally_new_kind","time_bucket":"2026-07-03T14:00:00Z",
         "local_confidence":0.8,"local_reasons":["beaconing_candidate"],
         "observation_count":1,"distinct_asset_count":1},
        {"signal_id":"badbucket","kind":"behavior_summary","time_bucket":"2026-07-03T14:30:00Z",
         "behavior":"dns_beaconing_candidate","local_confidence":0.8,"local_reasons":["beaconing_candidate"],
         "observation_count":1,"distinct_asset_count":1}
      ]}`)
	b, rejected, err := ParseAndValidate(body)
	if err != nil {
		t.Fatalf("expected no whole-batch error, got %v", err)
	}
	if len(b.Signals) != 1 {
		t.Fatalf("expected 1 accepted signal, got %d", len(b.Signals))
	}
	if rejected != 3 {
		t.Fatalf("expected 3 rejected, got %d", rejected)
	}
}

// TestCountUpperBoundsRejected is the finding #2 regression: observation_count
// must be in [1,10000] and distinct_asset_count in [1,500] (002 §4). The upper
// bound was unenforced. These are per-signal STRUCTURAL rejections (reflected in
// the rejected count), not a whole-batch 422 — matching how other structural
// failures are handled. Boundary values (10000 / 500) are accepted; one-over
// (10001 / 501) is rejected.
func TestCountUpperBoundsRejected(t *testing.T) {
	// behavior_summary carries no domain material, so it isolates the count check.
	behaviorSig := func(obs, distinct int) string {
		return fmt.Sprintf(`{"signal_id":"s","kind":"behavior_summary","time_bucket":"2026-07-03T14:00:00Z",
          "behavior":"dns_beaconing_candidate","local_confidence":0.8,"local_reasons":["beaconing_candidate"],
          "observation_count":%d,"distinct_asset_count":%d}`, obs, distinct)
	}
	batch := func(sig string) []byte {
		return []byte(fmt.Sprintf(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
          "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[%s]}`, sig))
	}

	// Boundary values are accepted.
	for _, c := range []struct {
		name          string
		obs, distinct int
	}{
		{"obs_at_max", 10000, 1},
		{"distinct_at_max", 1, 500},
		{"both_at_max", 10000, 500},
	} {
		t.Run("accept_"+c.name, func(t *testing.T) {
			b, rejected, err := ParseAndValidate(batch(behaviorSig(c.obs, c.distinct)))
			if err != nil {
				t.Fatalf("boundary value must be accepted, got whole-batch err %v", err)
			}
			if rejected != 0 || len(b.Signals) != 1 {
				t.Fatalf("boundary value must be accepted, got rejected=%d accepted=%d", rejected, len(b.Signals))
			}
		})
	}

	// One-over values are per-signal rejected (not a whole-batch failure).
	for _, c := range []struct {
		name          string
		obs, distinct int
	}{
		{"obs_over_max", 10001, 1},
		{"distinct_over_max", 1, 501},
	} {
		t.Run("reject_"+c.name, func(t *testing.T) {
			b, rejected, err := ParseAndValidate(batch(behaviorSig(c.obs, c.distinct)))
			if err != nil {
				t.Fatalf("over-cap count must be a per-signal reject, not whole-batch err: %v", err)
			}
			if rejected != 1 {
				t.Fatalf("expected 1 rejected, got %d", rejected)
			}
			if len(b.Signals) != 0 {
				t.Fatalf("over-cap signal must not be accepted, got %d accepted", len(b.Signals))
			}
		})
	}
}

func TestDomainForbiddenOnCandidateKind(t *testing.T) {
	// domain present on high_confidence_domain_candidate is a strict-schema
	// unknown-key violation (domain not allowed for that kind) → whole batch 422.
	body := []byte(`{"schema_version":1,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"high_confidence_domain_candidate","time_bucket":"2026-07-03T14:00:00Z",
        "domain":"exact.badhost.example","etld_plus_one":"badhost.example","local_confidence":0.9,
        "local_reasons":["dga_candidate"],"observation_count":1,"distinct_asset_count":1}]}`)
	_, _, err := ParseAndValidate(body)
	se, ok := err.(*StrictError)
	if !ok {
		t.Fatalf("expected StrictError, got %T (%v)", err, err)
	}
	if se.Rule != "unknown_key" {
		t.Fatalf("expected unknown_key for forbidden domain field, got %s", se.Rule)
	}
}

func TestBadSchemaVersionEnvelope400(t *testing.T) {
	body := []byte(`{"schema_version":2,"batch_id":"b1","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z","signals":[]}`)
	_, _, err := ParseAndValidate(body)
	if _, ok := err.(*EnvelopeError); !ok {
		t.Fatalf("expected EnvelopeError, got %T (%v)", err, err)
	}
}

// --- Processor (dedup, idempotency, caps) ---

func newProcessor(t *testing.T, now time.Time) (*Processor, *store.DB) {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Processor{DB: db, Now: func() time.Time { return now }}, db
}

func TestProcessIdempotentDuplicateBatch(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	p, db := newProcessor(t, now)
	body := validBatch("dup-batch")

	res, err := p.Process("r1", body)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if res.Duplicate {
		t.Fatal("first ingest should not be duplicate")
	}
	if res.Accepted != 3 {
		t.Fatalf("expected 3 accepted, got %d", res.Accepted)
	}

	var rowsBefore int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&rowsBefore)

	// Replay the exact same batch_id.
	res2, err := p.Process("r1", body)
	if err != nil {
		t.Fatalf("replay ingest: %v", err)
	}
	if !res2.Duplicate {
		t.Fatal("replay must be duplicate:true")
	}
	if res2.Accepted != 3 || res2.Rejected != 0 {
		t.Fatalf("replay must echo original counts, got %+v", res2)
	}
	var rowsAfter int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&rowsAfter)
	if rowsAfter != rowsBefore {
		t.Fatalf("replay must not re-process: rows %d → %d", rowsBefore, rowsAfter)
	}
}

// TestProcessSameBatchIDTwoReporters is the finding #3 regression: idempotency is
// per-(reporter_id, batch_id). Reporter B submitting a batch whose UUID collides
// with a batch_id already recorded for reporter A must be processed independently
// — B must NOT receive duplicate:true (which would echo A's counts, a cross-
// reporter disclosure) and B's signals must NOT be silently dropped.
func TestProcessSameBatchIDTwoReporters(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	p, db := newProcessor(t, now)
	body := validBatch("shared-batch-id")

	resA, err := p.Process("reporterA", body)
	if err != nil {
		t.Fatalf("reporterA ingest: %v", err)
	}
	if resA.Duplicate || resA.Accepted != 3 {
		t.Fatalf("reporterA first ingest unexpected: %+v", resA)
	}

	// Reporter B reuses the identical batch_id.
	resB, err := p.Process("reporterB", body)
	if err != nil {
		t.Fatalf("reporterB ingest: %v", err)
	}
	if resB.Duplicate {
		t.Fatalf("reporterB must NOT be treated as a duplicate of reporterA's batch: %+v", resB)
	}
	if resB.Accepted != 3 {
		t.Fatalf("reporterB signals must be stored, got accepted=%d", resB.Accepted)
	}

	// Both reporters' signals are stored (6 rows: 3 indicators × 2 reporters).
	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&rows)
	if rows != 6 {
		t.Fatalf("both reporters' signals must persist, expected 6 rows, got %d", rows)
	}

	// Two independent receipts exist, keyed per reporter.
	var receipts int
	db.QueryRow(`SELECT COUNT(*) FROM ingest_receipts WHERE batch_id = 'shared-batch-id'`).Scan(&receipts)
	if receipts != 2 {
		t.Fatalf("expected 2 per-reporter receipts for the shared batch_id, got %d", receipts)
	}

	// And each reporter's own replay is still idempotent.
	resBReplay, err := p.Process("reporterB", body)
	if err != nil {
		t.Fatalf("reporterB replay: %v", err)
	}
	if !resBReplay.Duplicate {
		t.Fatalf("reporterB replay of its own batch must be duplicate:true, got %+v", resBReplay)
	}
}

func TestProcessDedupAcrossBatches(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	p, db := newProcessor(t, now)

	// Two different batch_ids carrying the SAME signal (reporter+kind+indicator+bucket).
	if _, err := p.Process("r1", validBatch("batch-A")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process("r1", validBatch("batch-B")); err != nil {
		t.Fatal(err)
	}
	// Same signals dedupe to one row each (3 distinct indicators).
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&n)
	if n != 3 {
		t.Fatalf("expected 3 deduped signal rows, got %d", n)
	}
}

func TestProcessPrivacyGateReturns422Error(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	p, _ := newProcessor(t, now)
	body := []byte(`{"schema_version":1,"batch_id":"bp","generated_at":"2026-07-03T14:15:02Z",
      "window_start":"2026-07-03T14:00:00Z","window_end":"2026-07-03T15:00:00Z",
      "signals":[{"signal_id":"s1","kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
        "domain":"printer.local","etld_plus_one":"badzone.example","local_confidence":0.9,
        "local_reasons":["known_bad"],"observation_count":1,"distinct_asset_count":1}]}`)
	_, err := p.Process("r1", body)
	if _, ok := err.(*StrictError); !ok {
		t.Fatalf("expected StrictError from Process, got %T (%v)", err, err)
	}
}

func TestSignalCapEnforced(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	p, db := newProcessor(t, now)
	day := "2026-07-03"
	// Pre-load the reporter near the daily signal cap.
	if err := db.AddCounters("r1", day, 0, MaxSignalsPerDay-2, 0, 0); err != nil {
		t.Fatal(err)
	}
	// Batch has 3 signals; only 2 fit under the cap → 1 rejected.
	res, err := p.Process("r1", validBatch("cap-batch"))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Accepted != 2 || res.Rejected != 1 {
		t.Fatalf("expected accepted=2 rejected=1 under cap, got %+v", res)
	}

	// A second reporter is unaffected by r1's cap.
	res2, err := p.Process("r2", validBatch("cap-batch-2"))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Accepted != 3 {
		t.Fatalf("second reporter should be unaffected, got %+v", res2)
	}
}

func TestBatchCapEnforced(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	p, db := newProcessor(t, now)
	day := "2026-07-03"
	if err := db.AddCounters("r1", day, MaxBatchesPerDay, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	_, err := p.Process("r1", validBatch("over-cap"))
	if _, ok := err.(*CapError); !ok {
		t.Fatalf("expected CapError, got %T (%v)", err, err)
	}
}

// TestConcurrentDuplicateBatchCountsOnce is the LOW finding regression: two (or
// more) concurrent Process calls for the SAME (reporter_id, batch_id) must bump
// the per-reporter daily counters exactly once. InsertReceipt is INSERT OR
// IGNORE and returns whether it "won" the insert; only the winner may AddCounters.
// Before the fix the bool was ignored, so a racing duplicate double-counted a
// single batch against the reporter's abuse caps.
func TestConcurrentDuplicateBatchCountsOnce(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	day := "2026-07-03"

	// Repeat to shake out scheduling: every iteration must count exactly once.
	for iter := 0; iter < 25; iter++ {
		p, db := newProcessor(t, now)
		body := validBatch(fmt.Sprintf("race-batch-%d", iter))

		const racers = 8
		var wg sync.WaitGroup
		errs := make([]error, racers)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_, errs[idx] = p.Process("r1", body)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("iter %d: concurrent Process errored: %v", iter, err)
			}
		}

		c, err := db.GetCounters("r1", day)
		if err != nil {
			t.Fatal(err)
		}
		if c.BatchesAccepted != 1 {
			t.Fatalf("iter %d: a single batch must count once, got batches_accepted=%d", iter, c.BatchesAccepted)
		}
		if c.SignalsAccepted != 3 {
			t.Fatalf("iter %d: signals must count once (3), got signals_accepted=%d", iter, c.SignalsAccepted)
		}
		// Exactly one receipt exists for the batch.
		var receipts int
		db.QueryRow(`SELECT COUNT(*) FROM ingest_receipts WHERE batch_id = ?`,
			fmt.Sprintf("race-batch-%d", iter)).Scan(&receipts)
		if receipts != 1 {
			t.Fatalf("iter %d: expected exactly 1 receipt, got %d", iter, receipts)
		}
	}
}

// sanity: ensure the fixture body itself is well-formed JSON
func TestFixtureIsValidJSON(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(validBatch("x"), &m); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
}
