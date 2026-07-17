package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fkViolationCount(t *testing.T, db *DB) int {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_check iteration: %v", err)
	}
	return n
}

func deviceExists(t *testing.T, db *DB, id string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE device_id = ?`, id).Scan(&n); err != nil {
		t.Fatalf("device exists %s: %v", id, err)
	}
	return n > 0
}

// TestConsolidateMACOwners_CollapsesRunaway proves the one-time cleanup collapses a
// burned-in MAC's duplicate owners to one deterministic survivor, hard-deletes the
// duplicates and their children, keeps foreign_key_check clean, preserves the
// survivor and unrelated devices, skips randomized MACs, and is idempotent.
func TestConsolidateMACOwners_CollapsesRunaway(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	macA := "00:00:5E:00:53:01" // burned-in, runaway
	macB := "00:00:5E:00:53:AA" // burned-in, clean single owner
	macR := "02:00:5E:00:53:07" // locally administered (randomized)

	// 4 owners of macA, oldest first -> survivor = "surv".
	seedMACOwner(t, db, "surv", base, macA, "lan", "sensor-a")
	seedMACOwner(t, db, "dup1", base.Add(time.Hour), macA, "lan", "sensor-a")
	seedMACOwner(t, db, "dup2", base.Add(2*time.Hour), macA, "lan", "sensor-a")
	seedMACOwner(t, db, "dup3", base.Add(3*time.Hour), macA, "lan", "sensor-a")
	// Unrelated clean device + a randomized 2-owner MAC (must be left alone).
	seedMACOwner(t, db, "other", base, macB, "lan", "sensor-a")
	seedMACOwner(t, db, "rand-a", base, macR, "lan", "sensor-a")
	seedMACOwner(t, db, "rand-b", base.Add(time.Hour), macR, "lan", "sensor-a")

	// Child rows on a duplicate that must be deleted/repointed, not orphaned.
	if _, err := db.Exec(`INSERT INTO device_networks (device_id, segment, ip_address, sensor_id, first_seen, last_seen)
		VALUES ('dup1','lan','192.0.2.90','sensor-a',?,?)`, base, base); err != nil {
		t.Fatalf("seed network: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO device_signals (device_id, field, value, source, confidence, first_observed, last_observed)
		VALUES ('dup1','vendor','Acme','oui',0.2,?,?)`, base, base); err != nil {
		t.Fatalf("seed signal: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO device_address_history
		(binding_id, device_id, address_type, address_value, segment, sensor_id, first_seen, last_seen, valid_from, evidence_source, confidence, created_at)
		VALUES (?, 'dup2','mac',?,'lan','sensor-a',?,?,?, 'event',0.9,?)`,
		uuid.NewString(), macA, base, base, base, base); err != nil {
		t.Fatalf("seed address history: %v", err)
	}
	// A confirm action on dup3 bound to dup3's MAC evidence -> must be dropped with
	// that evidence (it cannot dangle to a deleted evidence row).
	var evID string
	if err := db.QueryRow(`SELECT evidence_id FROM device_identity_evidence WHERE device_id='dup3' AND evidence_type='mac' LIMIT 1`).Scan(&evID); err != nil {
		t.Fatalf("read dup3 evidence: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO device_identity_actions
		(action_id, action_type, target_device_id, evidence_id, actor, reason, metadata, created_at)
		VALUES (?, 'confirm', 'dup3', ?, 'token:x', 'MAC Confirmed', '{}', ?)`, uuid.NewString(), evID, base); err != nil {
		t.Fatalf("seed confirm action: %v", err)
	}

	if n := countDevices(t, db); n != 7 {
		t.Fatalf("setup expected 7 devices, got %d", n)
	}

	rep, err := db.ConsolidateMACOwners(context.Background())
	if err != nil {
		t.Fatalf("consolidate: %v", err)
	}
	if rep.Groups != 1 || rep.AbsorbedCount != 3 || len(rep.Survivors) != 1 || rep.Survivors[0] != "surv" || !rep.FKClean {
		t.Fatalf("unexpected report: %+v", rep)
	}
	// macA collapses to surv; macB and both randomized owners remain -> 4 devices.
	if n := countDevices(t, db); n != 4 {
		t.Fatalf("post-consolidation device count = %d, want 4", n)
	}
	if !deviceExists(t, db, "surv") || !deviceExists(t, db, "other") || !deviceExists(t, db, "rand-a") || !deviceExists(t, db, "rand-b") {
		t.Fatal("survivor / unrelated / randomized owners must be preserved")
	}
	for _, gone := range []string{"dup1", "dup2", "dup3"} {
		if deviceExists(t, db, gone) {
			t.Fatalf("duplicate %s was not deleted", gone)
		}
	}
	if v := fkViolationCount(t, db); v != 0 {
		t.Fatalf("foreign_key_check found %d violation(s) after consolidation", v)
	}
	// The runaway MAC now resolves cleanly to the survivor.
	got := resolveStrengthMAC(t, db, base.Add(10*time.Hour), "sensor-a", "lan", macA)
	if got.DeviceID != "surv" {
		t.Fatalf("post-cleanup macA must resolve to survivor, got %+v", got)
	}
	// Idempotent: a second run finds nothing to do.
	rep2, err := db.ConsolidateMACOwners(context.Background())
	if err != nil {
		t.Fatalf("second consolidate: %v", err)
	}
	if rep2.Groups != 0 || rep2.AbsorbedCount != 0 {
		t.Fatalf("second run should be a no-op, got %+v", rep2)
	}
	if !rep2.FKClean {
		t.Fatalf("idempotent run must still execute foreign_key_check, got %+v", rep2)
	}
}

// TestConsolidateMACOwners_ExcludesMultiMACHardware proves conservatism: a device
// that carries a SECOND distinct active MAC is genuinely different hardware and is
// left as a separate owner rather than absorbed.
func TestConsolidateMACOwners_ExcludesMultiMACHardware(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	macA := "00:00:5E:00:53:01"
	macC := "00:00:5E:00:53:C0"

	seedMACOwner(t, db, "survA", base, macA, "lan", "sensor-a")
	seedMACOwner(t, db, "cleanA", base.Add(30*time.Minute), macA, "lan", "sensor-a")
	seedMACOwner(t, db, "dupA", base.Add(time.Hour), macA, "lan", "sensor-a")
	// Give dupA a second, distinct burned-in MAC -> ambiguous hardware.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.upsertIdentityEvidenceTx(tx, "dupA", "lan", "sensor-a",
		DeviceIdentityEvidenceInput{Type: "mac", Value: macC, Source: "event", Confidence: 0.95, Sensitive: true},
		base.Add(time.Hour), false); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rep, err := db.ConsolidateMACOwners(context.Background())
	if err != nil {
		t.Fatalf("consolidate: %v", err)
	}
	if rep.AbsorbedCount != 0 || rep.Groups != 0 {
		t.Fatalf("a group containing multi-MAC hardware must be skipped entirely, got %+v", rep)
	}
	if !deviceExists(t, db, "survA") || !deviceExists(t, db, "cleanA") || !deviceExists(t, db, "dupA") {
		t.Fatal("every owner must survive when any group member is ambiguous hardware")
	}
	var markerCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='mac_owner_consolidation_v1'`).Scan(&markerCount); err != nil {
		t.Fatalf("read completion marker: %v", err)
	}
	if markerCount != 1 || !rep.FKClean {
		t.Fatalf("no-op run must validate FKs and record completion: marker=%d report=%+v", markerCount, rep)
	}
}

// TestConsolidateMACOwners_CanonicalizesMergedChildEvidence keeps cleanup aligned
// with the resolver. Evidence retained on a soft-merged child still makes its
// canonical family an owner; consolidation must see that family, absorb the
// duplicate canonical root, and repoint the retained child to the survivor.
func TestConsolidateMACOwners_CanonicalizesMergedChildEvidence(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	mac := "00:00:5E:00:53:31"

	seedMACOwner(t, db, "survivor", base, mac, "lan", "sensor-a")
	if _, err := db.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, segment)
		VALUES ('canonical-duplicate', ?, ?, '', '', 'lan')`, base.Add(time.Hour), base.Add(time.Hour)); err != nil {
		t.Fatalf("seed canonical duplicate: %v", err)
	}
	seedMACOwner(t, db, "merged-child", base.Add(2*time.Hour), mac, "lan", "sensor-a")
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.mergeDevices(tx, "canonical-duplicate", "merged-child", "fixture"); err != nil {
		tx.Rollback()
		t.Fatalf("soft merge fixture: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}

	rep, err := db.ConsolidateMACOwners(context.Background())
	if err != nil {
		t.Fatalf("consolidate: %v", err)
	}
	if rep.Groups != 1 || rep.AbsorbedCount != 1 || !rep.FKClean {
		t.Fatalf("merged-child owner was not consolidated: %+v", rep)
	}
	if deviceExists(t, db, "canonical-duplicate") {
		t.Fatal("duplicate canonical root survived consolidation")
	}
	var redirect string
	if err := db.QueryRow(`SELECT merged_into_device_id FROM devices WHERE device_id='merged-child'`).Scan(&redirect); err != nil {
		t.Fatalf("read retained child redirect: %v", err)
	}
	if redirect != "survivor" {
		t.Fatalf("retained child redirect=%q, want survivor", redirect)
	}
	got := resolveStrengthMAC(t, db, base.Add(3*time.Hour), "sensor-a", "lan", mac)
	if got.DeviceID != "survivor" || got.Reason != "mac_identity_evidence" {
		t.Fatalf("post-cleanup MAC resolution = %+v", got)
	}
}
