package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// TestSplitSQLStatements guards the migration-splitter that lets the runner apply
// statements one at a time. The tricky case is a semicolon INSIDE a string
// literal (migration 017 has one) — a naive split would corrupt that INSERT.
func TestSplitSQLStatements(t *testing.T) {
	script := `-- header comment
ALTER TABLE devices ADD COLUMN a TEXT DEFAULT '';
INSERT INTO x (c) VALUES ('has ; a semicolon; inside it');
/* block ; comment */
CREATE TABLE y (id TEXT); -- trailing line comment
`
	got := splitSQLStatements(script)
	// Expect: the ALTER, the INSERT, and the CREATE. Comment-only fragments do not
	// count as executable statements.
	var exec []string
	for _, s := range got {
		if !isNoOpSQL(s) {
			exec = append(exec, s)
		}
	}
	if len(exec) != 3 {
		t.Fatalf("expected 3 executable statements, got %d: %#v", len(exec), exec)
	}
	if !strings.Contains(exec[1], "has ; a semicolon; inside it") {
		t.Errorf("semicolons inside a string literal must not split the statement: %q", exec[1])
	}
}

// TestFreshMigrationsProduceCompleteSchema runs the REAL migration files against
// a fresh DB and asserts a final-schema manifest — the check that was missing and
// let migration 012 silently skip suppression_rules (beta-gate B3). It also
// verifies the exact query that regressed (SELECT ... FROM suppression_rules).
func TestFreshMigrationsProduceCompleteSchema(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	migDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "siem", "migrations")
	if _, err := os.Stat(migDir); err != nil {
		t.Skipf("real migrations dir not found (%s): %v", migDir, err)
	}
	t.Setenv("VEDETTA_MIGRATIONS_DIR", migDir)

	dbPath := filepath.Join(t.TempDir(), "manifest.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open fresh DB with real migrations: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	wantTables := []string{
		"events", "devices", "sensors", "api_tokens", "scan_targets",
		"threat_indicators", "whitelist_rules", "suppression_rules",
		"device_address_history", "device_address_binding_strength", "device_address_binding_validity",
		"device_identity_evidence", "device_identity_evidence_strength", "device_identity_evidence_validity", "device_identity_actions",
		"event_detection_evidence", "findings", "finding_events", "finding_evidence",
		"finding_status_history", "finding_suppression_rules", "finding_suppression_history", "collection_source_health",
		"sensor_lifecycle_events",
		"sensor_report_time_normalizations",
		"sensor_report_time_raw_epochs",
		"sensor_report_time_receipts",
		"arp_cache_states",
		"arp_cache_delivery_epochs",
		"schema_migrations",
	}
	for _, tbl := range wantTables {
		var name string
		if err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&name); err != nil {
			t.Errorf("expected table %q to exist after fresh migrations: %v", tbl, err)
		}
	}

	// The endpoint that returned 500 must now work: querying suppression_rules
	// must not fail with "no such table".
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM suppression_rules`).Scan(&count); err != nil {
		t.Errorf("SELECT from suppression_rules failed (the B3 regression): %v", err)
	}

	for _, col := range []string{"device_id", "identity_confidence", "identity_reason", "identity_evidence",
		"origin", "sensor_id", "outcome", "disposition", "suppression_rule_id"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name=?`, col).Scan(&count); err != nil || count != 1 {
			t.Errorf("expected events.%s after migration 025 (count=%d err=%v)", col, count, err)
		}
	}
	for _, col := range []string{"merged_into_device_id", "merge_action_id", "merged_at"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name=?`, col).Scan(&count); err != nil || count != 1 {
			t.Errorf("expected devices.%s after migration 025 (count=%d err=%v)", col, count, err)
		}
	}
	for _, col := range []string{"removed_at", "removed_by_token_id", "removal_reason"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name=?`, col).Scan(&count); err != nil || count != 1 {
			t.Errorf("expected sensors.%s after migration 026 (count=%d err=%v)", col, count, err)
		}
	}
	for _, col := range []string{"event_id", "sensor_id", "event_type", "actor", "reason", "details", "created_at"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensor_lifecycle_events') WHERE name=?`, col).Scan(&count); err != nil || count != 1 {
			t.Errorf("expected sensor_lifecycle_events.%s after migration 026 (count=%d err=%v)", col, count, err)
		}
	}
	for _, col := range []string{"sensor_id", "segment", "ip_address", "state", "mac_hmac",
		"observed_at", "delivery_epoch_order", "delivery_sequence", "updated_at"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('arp_cache_states') WHERE name=?`, col).Scan(&count); err != nil || count != 1 {
			t.Errorf("expected arp_cache_states.%s after migration 030 (count=%d err=%v)", col, count, err)
		}
	}
	for _, col := range []string{"epoch_order", "sensor_id", "delivery_epoch", "issued_at", "activated_at", "ever_activated_at"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('arp_cache_delivery_epochs') WHERE name=?`, col).Scan(&count); err != nil || count != 1 {
			t.Errorf("expected arp_cache_delivery_epochs.%s after migration 030 (count=%d err=%v)", col, count, err)
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type='index' AND name='ux_arp_cache_delivery_active_sensor'
		AND sql LIKE '%WHERE activated_at IS NOT NULL%'`).Scan(&count); err != nil || count != 1 {
		t.Errorf("expected partial unique active ARP epoch index after migration 030 (count=%d err=%v)", count, err)
	}

	// Compatibility invariant: old-style inserts do not guess a historical
	// device from the current inventory projection.
	if _, err := db.Exec(`INSERT INTO events(event_id,timestamp,event_type,source_hash)
		VALUES ('pre-identity-event','2026-01-01T00:00:00Z','dns_query','local-hash')`); err != nil {
		t.Fatalf("insert legacy-shaped event: %v", err)
	}
	var deviceID any
	if err := db.QueryRow(`SELECT device_id FROM events WHERE event_id='pre-identity-event'`).Scan(&deviceID); err != nil {
		t.Fatalf("read legacy-shaped event identity: %v", err)
	}
	if deviceID != nil {
		t.Errorf("legacy-shaped event was backfilled/guessed: %#v", deviceID)
	}
	var outcome string
	if err := db.QueryRow(`SELECT outcome FROM events WHERE event_id='pre-identity-event'`).Scan(&outcome); err != nil {
		t.Fatalf("read legacy-shaped event outcome: %v", err)
	}
	if outcome != "observed" {
		t.Errorf("legacy-shaped event outcome = %q, want observed", outcome)
	}

	// Real migrations must accept standard DNS types outside the short legacy
	// enum, and a non-PK constraint failure must never masquerade as a duplicate.
	record := ProcessedEventRecord{Event: models.Event{
		EventID: "query-type-https", Timestamp: time.Now().UTC(), EventType: "dns_query",
		SourceHash: "local-hash", Domain: "service.example", QueryType: "HTTPS", Metadata: `{}`,
	}, IdentityEvidence: []byte(`{}`), Origin: "test", Disposition: models.DispositionActive}
	persisted, err := db.PersistProcessedEvent(context.Background(), record)
	if err != nil || !persisted.Inserted || persisted.Duplicate {
		t.Fatalf("persist standard HTTPS query = %+v err=%v", persisted, err)
	}
	record.Event.EventID = "invalid-event-type"
	record.Event.EventType = "not_a_real_event"
	persisted, err = db.PersistProcessedEvent(context.Background(), record)
	if err == nil || persisted.Duplicate {
		t.Fatalf("non-PK constraint was treated as duplicate: result=%+v err=%v", persisted, err)
	}
}
