package export

import "testing"

// cleanBatch is a contract-conformant serialized batch (contract §7 shape).
const cleanBatch = `{
  "schema_version": 1,
  "batch_id": "6b2f4c8e-1a3d-4f5b-9c7e-2d4f6a8b0c1e",
  "generated_at": "2026-07-03T14:15:02Z",
  "window_start": "2026-07-03T14:00:00Z",
  "window_end": "2026-07-03T14:15:00Z",
  "signals": [
    {"signal_id":"3c5e7a9b-2d4f-4a6c-8e0b-1f3a5c7e9b0d","kind":"known_bad_domain_hit",
     "time_bucket":"2026-07-03T14:00:00Z","domain":"c2-payload.badzone.example",
     "etld_plus_one":"badzone.example","local_confidence":0.99,
     "local_reasons":["known_bad","threat_feed_match","c2_candidate"],
     "observation_count":4,"distinct_asset_count":2,"blocked_count":4}
  ]
}`

func TestLeakScanClean(t *testing.T) {
	if v := LeakScan([]byte(cleanBatch)); len(v) != 0 {
		t.Errorf("clean batch flagged: %v", v)
	}
}

// Each seeded violation must be caught.
func TestLeakScanCatchesViolations(t *testing.T) {
	cases := map[string]string{
		"ipv4":           `{"schema_version":1,"signals":[{"etld_plus_one":"192.0.2.7"}]}`,
		"ipv6":           `{"schema_version":1,"signals":[{"domain":"2001:db8::1"}]}`,
		"mac":            `{"schema_version":1,"signals":[{"domain":"00:00:5E:00:53:2A"}]}`,
		"unknown_key":    `{"schema_version":1,"signals":[{"source_hash":"abc"}]}`,
		"top_key":        `{"schema_version":1,"reporter_id":"x","signals":[]}`,
		"private_suffix": `{"schema_version":1,"signals":[{"domain":"nas.local"}]}`,
		"url_syntax":     `{"schema_version":1,"signals":[{"domain":"evil.example/path"}]}`,
		"userinfo":       `{"schema_version":1,"signals":[{"domain":"user@evil.example"}]}`,
		"bad_reason":     `{"schema_version":1,"signals":[{"local_reasons":["free_text_reason"]}]}`,
		"arpa":           `{"schema_version":1,"signals":[{"domain":"5.2.0.192.in-addr.arpa"}]}`,
	}
	for name, batch := range cases {
		t.Run(name, func(t *testing.T) {
			if v := LeakScan([]byte(batch)); len(v) == 0 {
				t.Errorf("expected violation for %s, got none", name)
			}
		})
	}
}
