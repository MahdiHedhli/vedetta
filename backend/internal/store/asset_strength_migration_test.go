package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func migrationFilesThrough(t *testing.T, dir, cutoff string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") || len(name) < 3 || name[:3] > cutoff {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	return files
}

func TestMigration028PopulatedUpgradePreservesParentsActionsAndFKs(t *testing.T) {
	migrationDir := findMigrationsDir(t)
	dbPath := filepath.Join(t.TempDir(), "upgrade-027.db")
	raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("open raw 027 fixture: %v", err)
	}
	legacy := &DB{DB: raw}
	if _, err := legacy.Exec(`CREATE TABLE schema_migrations (
		id TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`); err != nil {
		t.Fatalf("create migration ledger: %v", err)
	}
	if err := legacy.applyFileMigrations(context.Background(), migrationDir,
		migrationFilesThrough(t, migrationDir, "027")); err != nil {
		t.Fatalf("apply migrations through 027: %v", err)
	}
	var absent int
	if err := legacy.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table'
		AND name IN ('device_address_binding_strength','device_address_binding_validity',
			'device_identity_evidence_strength','device_identity_evidence_validity')`).Scan(&absent); err != nil {
		t.Fatal(err)
	}
	if absent != 0 {
		t.Fatalf("027 fixture already has %d strength table(s)", absent)
	}

	base := time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC)
	if _, err := legacy.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, segment)
		VALUES ('device-028', ?, ?, '192.0.2.208', '00:00:5E:00:53:D0',
		'synthetic-028', 'Example Vendor', 'lan')`, base, base); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO device_address_history
		(binding_id, device_id, address_type, address_value, segment, sensor_id,
		 first_seen, last_seen, valid_from, evidence_source, confidence, created_at)
		VALUES ('binding-028', 'device-028', 'ip', '192.0.2.208', 'lan', 'sensor-028',
		 ?, ?, ?, 'legacy_source', 0.62, ?)`, base, base, base, base); err != nil {
		t.Fatalf("seed address binding: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO device_identity_evidence
		(evidence_id, device_id, evidence_type, value_hmac, segment, sensor_id, source,
		 confidence, first_seen, last_seen, valid_from, operator_confirmed, created_at)
		VALUES ('evidence-028', 'device-028', 'dhcp_client_id', ?, 'lan', 'sensor-028',
		 'legacy_source', 0.83, ?, ?, ?, TRUE, ?)`, strings.Repeat("ab", 32), base, base, base, base); err != nil {
		t.Fatalf("seed identity evidence: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO device_identity_actions
		(action_id, action_type, target_device_id, evidence_id, actor, reason, created_at)
		VALUES ('action-028', 'confirm', 'device-028', 'evidence-028',
		'test-admin', 'synthetic migration fixture', ?)`, base); err != nil {
		t.Fatalf("seed identity action: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close 027 fixture: %v", err)
	}

	t.Setenv("VEDETTA_MIGRATIONS_DIR", migrationDir)
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("upgrade populated 027 database through 028: %v", err)
	}
	var head string
	if err := db.QueryRow(`SELECT MAX(id) FROM schema_migrations`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(head, "030") {
		t.Fatalf("migration head = %q, want 030_*", head)
	}

	for table, want := range map[string]int{
		"device_address_history":            1,
		"device_identity_evidence":          1,
		"device_identity_actions":           1,
		"device_address_binding_strength":   1,
		"device_address_binding_validity":   1,
		"device_identity_evidence_strength": 1,
		"device_identity_evidence_validity": 1,
	} {
		var got int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}

	var addressAt, evidenceAt time.Time
	var addressSource, evidenceSource string
	var addressConfidence, evidenceConfidence float64
	var confirmed bool
	if err := db.QueryRow(`SELECT observed_at, source, confidence
		FROM device_address_binding_strength WHERE binding_id='binding-028'`).
		Scan(&addressAt, &addressSource, &addressConfidence); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT observed_at, source, confidence, operator_confirmed
		FROM device_identity_evidence_strength WHERE evidence_id='evidence-028'`).
		Scan(&evidenceAt, &evidenceSource, &evidenceConfidence, &confirmed); err != nil {
		t.Fatal(err)
	}
	if !addressAt.Equal(base) || addressSource != "legacy_source" || addressConfidence != 0.62 {
		t.Fatalf("address baseline = %s/%q/%.2f", addressAt, addressSource, addressConfidence)
	}
	if !evidenceAt.Equal(base) || evidenceSource != "legacy_source" || evidenceConfidence != 0.83 || !confirmed {
		t.Fatalf("evidence baseline = %s/%q/%.2f/confirmed=%v", evidenceAt, evidenceSource, evidenceConfidence, confirmed)
	}
	var addressValidFrom, addressValidUntil, evidenceValidFrom, evidenceValidUntil time.Time
	if err := db.QueryRow(`SELECT valid_from, valid_until FROM device_address_binding_validity
		WHERE binding_id='binding-028'`).Scan(&addressValidFrom, &addressValidUntil); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT valid_from, valid_until FROM device_identity_evidence_validity
		WHERE evidence_id='evidence-028'`).Scan(&evidenceValidFrom, &evidenceValidUntil); err != nil {
		t.Fatal(err)
	}
	if !addressValidFrom.Equal(base) || !addressValidUntil.Equal(base.Add(temporalAddressResolutionWindow)) {
		t.Fatalf("address validity baseline = [%s,%s]", addressValidFrom, addressValidUntil)
	}
	if !evidenceValidFrom.Equal(base) || !evidenceValidUntil.Equal(base.Add(mdnsNameRecencyWindow)) {
		t.Fatalf("evidence validity baseline = [%s,%s]", evidenceValidFrom, evidenceValidUntil)
	}

	var violations int
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		violations++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if violations != 0 {
		t.Fatalf("foreign_key_check found %d violation(s)", violations)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Both the migration inserts and runtime self-heal are idempotent on reopen.
	db, err = Open(dbPath)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer db.Close()
	var addressRows, addressValidityRows, evidenceRows, evidenceValidityRows, actionRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_strength`).Scan(&addressRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_strength`).Scan(&evidenceRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_validity`).Scan(&addressValidityRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_validity`).Scan(&evidenceValidityRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_actions WHERE action_id='action-028'`).Scan(&actionRows); err != nil {
		t.Fatal(err)
	}
	if addressRows != 1 || addressValidityRows != 1 || evidenceRows != 1 || evidenceValidityRows != 1 || actionRows != 1 {
		t.Fatalf("reopen changed migrated rows: address=%d/%d evidence=%d/%d action=%d",
			addressRows, addressValidityRows, evidenceRows, evidenceValidityRows, actionRows)
	}
}

func TestStrengthHistoryInlineFallbackSchemaAndBackfillAreIdempotent(t *testing.T) {
	db := newCorrelationDB(t)
	var migrations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 0 {
		t.Fatalf("test did not exercise inline fallback; migration ledger has %d rows", migrations)
	}
	for _, table := range []string{"device_address_binding_strength", "device_address_binding_validity",
		"device_identity_evidence_strength", "device_identity_evidence_validity"} {
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil || exists != 1 {
			t.Fatalf("inline fallback table %s: exists=%d err=%v", table, exists, err)
		}
	}

	observeAsset(t, db, time.Date(2026, 7, 15, 16, 0, 0, 0, time.UTC),
		"sensor-inline", "lan", "192.0.2.209", "00:00:5E:00:53:D1", "inline-209")
	var beforeAddress, beforeAddressValidity, beforeEvidence, beforeEvidenceValidity int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_strength`).Scan(&beforeAddress); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_strength`).Scan(&beforeEvidence); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_validity`).Scan(&beforeAddressValidity); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_validity`).Scan(&beforeEvidenceValidity); err != nil {
		t.Fatal(err)
	}
	if err := db.ensureAssetCenteredSchema(); err != nil {
		t.Fatalf("first inline self-heal: %v", err)
	}
	if err := db.ensureAssetCenteredSchema(); err != nil {
		t.Fatalf("second inline self-heal: %v", err)
	}
	var afterAddress, afterAddressValidity, afterEvidence, afterEvidenceValidity int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_strength`).Scan(&afterAddress); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_strength`).Scan(&afterEvidence); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_validity`).Scan(&afterAddressValidity); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_validity`).Scan(&afterEvidenceValidity); err != nil {
		t.Fatal(err)
	}
	if afterAddress != beforeAddress || afterAddressValidity != beforeAddressValidity ||
		afterEvidence != beforeEvidence || afterEvidenceValidity != beforeEvidenceValidity {
		t.Fatalf("inline self-heal duplicated baselines: address %d/%d->%d/%d evidence %d/%d->%d/%d",
			beforeAddress, beforeAddressValidity, afterAddress, afterAddressValidity,
			beforeEvidence, beforeEvidenceValidity, afterEvidence, afterEvidenceValidity)
	}
}

func TestMigration028AcceptsPopulatedInlineFallbackDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "inline-then-files.db")
	emptyMigrations := filepath.Join(t.TempDir(), "empty-migrations")
	if err := os.Mkdir(emptyMigrations, 0o700); err != nil {
		t.Fatalf("create empty migrations directory: %v", err)
	}

	// Model a binary-only installation: migrate() finds an explicitly configured
	// directory but no SQL files, so the inline fallback creates and populates the
	// event-time child tables without recording migration 028 in the ledger.
	t.Setenv("VEDETTA_MIGRATIONS_DIR", emptyMigrations)
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open inline-fallback database: %v", err)
	}
	observedAt := time.Date(2026, 7, 15, 17, 0, 0, 0, time.UTC)
	observeAsset(t, db, observedAt, "sensor-inline-upgrade", "lan",
		"192.0.2.210", "00:00:5E:00:53:D2", "inline-upgrade-210")

	childTables := []string{
		"device_address_binding_strength",
		"device_address_binding_validity",
		"device_identity_evidence_strength",
		"device_identity_evidence_validity",
	}
	before := make(map[string]int, len(childTables))
	for _, table := range childTables {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			db.Close()
			t.Fatalf("count inline %s rows: %v", table, err)
		}
		before[table] = count
		if before[table] == 0 {
			db.Close()
			t.Fatalf("inline fallback did not populate %s", table)
		}
	}
	var migration028Before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations
		WHERE id='028_asset_identity_strength_history.sql'`).Scan(&migration028Before); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if migration028Before != 0 {
		db.Close()
		t.Fatalf("inline fixture unexpectedly recorded migration 028: %d", migration028Before)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close inline-fallback database: %v", err)
	}

	// Later, the same installation gains the packaged SQL migration directory.
	// Migration 028 must recognize its existing child rows, record itself, and
	// leave the populated timelines unchanged.
	t.Setenv("VEDETTA_MIGRATIONS_DIR", findMigrationsDir(t))
	db, err = Open(dbPath)
	if err != nil {
		t.Fatalf("open inline database with filesystem migrations: %v", err)
	}
	defer db.Close()

	for _, table := range childTables {
		var after int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&after); err != nil {
			t.Fatalf("count migrated %s rows: %v", table, err)
		}
		if after != before[table] {
			t.Fatalf("migration changed %s rows: %d -> %d", table, before[table], after)
		}
	}
	for _, migration := range []string{
		"028_asset_identity_strength_history.sql",
		"029_sensor_report_time_raw_epochs.sql",
		"030_arp_cache_states.sql",
	} {
		var applied int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE id=?`, migration).Scan(&applied); err != nil {
			t.Fatalf("check migration %s: %v", migration, err)
		}
		if applied != 1 {
			t.Fatalf("migration %s ledger rows = %d, want 1", migration, applied)
		}
	}

	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		var table, parent string
		var rowID, fkID int
		if err := rows.Scan(&table, &rowID, &parent, &fkID); err != nil {
			t.Fatalf("scan foreign-key violation: %v", err)
		}
		t.Fatalf("foreign-key violation after inline upgrade: table=%s row=%d parent=%s fk=%d",
			table, rowID, parent, fkID)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestMigration028ClampsMaxDateValidityBackfill(t *testing.T) {
	migrationDir := findMigrationsDir(t)
	dbPath := filepath.Join(t.TempDir(), "upgrade-max-date.db")
	raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	legacy := &DB{DB: raw}
	if _, err := legacy.Exec(`CREATE TABLE schema_migrations (
		id TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.applyFileMigrations(context.Background(), migrationDir,
		migrationFilesThrough(t, migrationDir, "027")); err != nil {
		t.Fatal(err)
	}
	nearMax := time.Date(9999, 12, 31, 23, 59, 0, 0, time.UTC)
	if _, err := legacy.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, segment)
		VALUES ('device-max', ?, ?, '192.0.2.250', '', 'lan')`, nearMax, nearMax); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO device_address_history
		(binding_id, device_id, address_type, address_value, segment, sensor_id,
		 first_seen, last_seen, valid_from, evidence_source, confidence, created_at)
		VALUES ('binding-max', 'device-max', 'ip', '192.0.2.250', 'lan', 'sensor-max',
		 ?, ?, ?, 'legacy', 0.8, ?)`, nearMax, nearMax, nearMax, nearMax); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO device_identity_evidence
		(evidence_id, device_id, evidence_type, value_hmac, segment, sensor_id, source,
		 confidence, first_seen, last_seen, valid_from, created_at)
		VALUES ('evidence-max', 'device-max', 'hostname', ?, 'lan', 'sensor-max', 'legacy',
		 0.7, ?, ?, ?, ?)`, strings.Repeat("cd", 32), nearMax, nearMax, nearMax, nearMax); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("VEDETTA_MIGRATIONS_DIR", migrationDir)
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("upgrade max-date legacy rows: %v", err)
	}
	defer db.Close()
	for table, parent := range map[string]string{
		"device_address_binding_validity":   "binding-max",
		"device_identity_evidence_validity": "evidence-max",
	} {
		column := "binding_id"
		if strings.Contains(table, "identity") {
			column = "evidence_id"
		}
		var got time.Time
		if err := db.QueryRow(`SELECT valid_until FROM `+table+` WHERE `+column+`=?`, parent).Scan(&got); err != nil {
			t.Fatalf("read %s clamp: %v", table, err)
		}
		if !got.Equal(maxSQLiteIdentityTime) {
			t.Fatalf("%s valid_until = %s, want %s", table, got, maxSQLiteIdentityTime)
		}
	}
}

func TestMigration028MalformedLegacyDateFailsLoudly(t *testing.T) {
	for _, malformed := range []struct {
		name   string
		column string
		value  string
	}{
		{name: "unparseable-last-seen", column: "last_seen", value: "not-a-sqlite-date"},
		{name: "unparseable-valid-from", column: "valid_from", value: "not-a-sqlite-date"},
		{name: "impossible-calendar-date", column: "valid_from", value: "2026-02-30 09:00:00"},
		{name: "noncanonical-lowercase-zone", column: "last_seen", value: "2026-07-15T09:00:00z"},
		{name: "noncanonical-surrounding-whitespace", column: "valid_from", value: "2026-07-15 09:00:00 "},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			migrationDir := findMigrationsDir(t)
			dbPath := filepath.Join(t.TempDir(), "upgrade-malformed-date.db")
			raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			legacy := &DB{DB: raw}
			if _, err := legacy.Exec(`CREATE TABLE schema_migrations (
				id TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if err := legacy.applyFileMigrations(context.Background(), migrationDir,
				migrationFilesThrough(t, migrationDir, "027")); err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC)
			if _, err := legacy.Exec(`INSERT INTO devices
				(device_id, first_seen, last_seen, ip_address, mac_address, segment)
				VALUES ('device-bad-date', ?, ?, '192.0.2.251', '', 'lan')`, base, base); err != nil {
				t.Fatal(err)
			}
			lastSeen, validFrom := any(base), any(base)
			if malformed.column == "last_seen" {
				lastSeen = malformed.value
			} else {
				validFrom = malformed.value
			}
			if _, err := legacy.Exec(`INSERT INTO device_address_history
				(binding_id, device_id, address_type, address_value, segment, sensor_id,
				 first_seen, last_seen, valid_from, evidence_source, confidence, created_at)
				VALUES ('binding-bad-date', 'device-bad-date', 'ip', '192.0.2.251', 'lan', 'sensor-bad',
				 ?, ?, ?, 'legacy', 0.8, ?)`, base, lastSeen, validFrom, base); err != nil {
				t.Fatal(err)
			}
			err = legacy.applyFileMigrations(context.Background(), migrationDir,
				[]string{"028_asset_identity_strength_history.sql"})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "invalid temporal parent") {
				t.Fatalf("malformed legacy %s migration error = %v, want strict temporal preflight failure", malformed.name, err)
			}
			var applied int
			if err := legacy.QueryRow(`SELECT COUNT(*) FROM schema_migrations
				WHERE id='028_asset_identity_strength_history.sql'`).Scan(&applied); err != nil {
				t.Fatal(err)
			}
			if applied != 0 {
				t.Fatal("failed migration 028 was recorded as applied")
			}
		})
	}
}

func TestEnsureAssetStrengthHistoryMalformedDateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name           string
		value          string
		deleteValidity bool
		deleteStrength bool
		childTable     string
	}{
		{name: "missing-validity-child", value: "2026-02-30 09:30:00", deleteValidity: true, childTable: "device_address_binding_validity"},
		{name: "missing-strength-child", value: "2026-07-15T09:30:00z", deleteStrength: true, childTable: "device_address_binding_strength"},
		{name: "whitespace-missing-strength-child", value: " 2026-07-15 09:30:00", deleteStrength: true, childTable: "device_address_binding_strength"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newCorrelationDB(t)
			base := time.Date(2026, 7, 15, 9, 30, 0, 0, time.UTC)
			deviceID := observeAsset(t, db, base, "sensor-bad", "lan", "192.0.2.252",
				"00:00:5E:00:53:FC", "bad-date-host")
			var bindingID string
			if err := db.QueryRow(`SELECT binding_id FROM device_address_history
				WHERE device_id=? AND address_type='ip'`, deviceID).Scan(&bindingID); err != nil {
				t.Fatal(err)
			}
			if tc.deleteValidity {
				if _, err := db.Exec(`DELETE FROM device_address_binding_validity WHERE binding_id=?`, bindingID); err != nil {
					t.Fatal(err)
				}
			}
			if tc.deleteStrength {
				if _, err := db.Exec(`DELETE FROM device_address_binding_strength WHERE binding_id=?`, bindingID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`UPDATE device_address_history SET valid_from=? WHERE binding_id=?`, tc.value, bindingID); err != nil {
				t.Fatal(err)
			}

			err := db.ensureAssetStrengthHistory()
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "invalid temporal parent") {
				t.Fatalf("runtime malformed timestamp error = %v, want strict fail-closed validation", err)
			}
			var children int
			if err := db.QueryRow(`SELECT COUNT(*) FROM `+tc.childTable+` WHERE binding_id=?`,
				bindingID).Scan(&children); err != nil {
				t.Fatal(err)
			}
			if children != 0 {
				t.Fatalf("runtime self-heal partially backfilled corrupt binding: %d child rows", children)
			}
		})
	}
}
