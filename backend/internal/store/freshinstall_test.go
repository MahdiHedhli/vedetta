package store

// Regression tests for the UniFi firewall ingestion feature (spec 001):
//   - migration 017 seeds the default firewall whitelist rules and widens the
//     api_tokens.scope CHECK to include 'ingest';
//   - the store's inline fallback schema (the path go tests hit when migration
//     files are not found) accepts an ingest-scoped token;
//   - the tag/source-IP event whitelist (IsEventWhitelisted) matches firewall
//     events without suppressing DNS rules.
//
// All values are synthetic / documentation-reserved per the constitution
// (RFC 5737 IPs, 00:00:5E:00:53:xx MACs).

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// findMigrationsDir walks up from this source file to locate the repo-root
// siem/migrations directory.
func findMigrationsDir(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(sourceFile)
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "siem", "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate siem/migrations directory walking up from test file")
	return ""
}

// buildBaseState stands up the tables migration 017 depends on (events schema,
// whitelist_rules, api_tokens, and its sensors FK) on a fresh raw sqlite db,
// using the already-committed migration files that apply cleanly as raw SQL.
// This mirrors the realistic pre-017 production state (001 already carries the
// final events shape; 004/013/014 add the other tables 017 touches).
func buildBaseState(t *testing.T, raw *sql.DB, migDir string) {
	t.Helper()
	for _, f := range []string{
		"001_init.sql",
		"004_sensors.sql",
		"013_whitelist_rules.sql",
		"014_api_tokens.sql",
	} {
		b, err := os.ReadFile(filepath.Join(migDir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("apply base migration %s: %v", f, err)
		}
	}
}

// TestMigration017_SeedsAndScopeWidening applies migration 017 on top of the
// realistic pre-017 schema and asserts:
//   - the three default firewall whitelist rules are seeded (category firewall,
//     is_default TRUE) with the expected tag_match values;
//   - the api_tokens.scope CHECK now accepts 'ingest' and still rejects unknown
//     scopes;
//   - the seed half is idempotent (INSERT OR IGNORE) on re-run;
//   - PRAGMA integrity_check reports ok.
func TestMigration017_SeedsAndScopeWidening(t *testing.T) {
	migDir := findMigrationsDir(t)

	dbPath := filepath.Join(t.TempDir(), "state.db")
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer raw.Close()

	buildBaseState(t, raw, migDir)

	sql017, err := os.ReadFile(filepath.Join(migDir, "017_unifi_firewall_defaults.sql"))
	if err != nil {
		t.Fatalf("read migration 017: %v", err)
	}
	if _, err := raw.Exec(string(sql017)); err != nil {
		t.Fatalf("apply migration 017: %v", err)
	}

	// Seeded firewall defaults present with expected tag_match.
	wantRules := map[string]string{
		"wl-fw-wan-scan-rollup":     "wan_scan_noise",
		"wl-fw-multicast-broadcast": "fw:multicast",
		"wl-fw-self-scan":           "",
	}
	for ruleID, wantTag := range wantRules {
		var tagMatch, category string
		var isDefault bool
		err := raw.QueryRow(
			`SELECT tag_match, category, is_default FROM whitelist_rules WHERE rule_id = ?`, ruleID,
		).Scan(&tagMatch, &category, &isDefault)
		if err != nil {
			t.Fatalf("seeded firewall rule %q missing after migration 017: %v", ruleID, err)
		}
		if tagMatch != wantTag {
			t.Errorf("rule %q tag_match = %q, want %q", ruleID, tagMatch, wantTag)
		}
		if category != "firewall" || !isDefault {
			t.Errorf("rule %q category/is_default = %q/%v, want firewall/true", ruleID, category, isDefault)
		}
	}

	// api_tokens.scope CHECK now allows 'ingest'.
	if _, err := raw.Exec(
		`INSERT INTO api_tokens (token_id, token_hash, scope, label) VALUES ('t-ingest', 'h-ingest', 'ingest', 'test')`,
	); err != nil {
		t.Errorf("inserting ingest-scoped token after migration 017 failed: %v", err)
	}
	// ...and still rejects an unknown scope.
	if _, err := raw.Exec(
		`INSERT INTO api_tokens (token_id, token_hash, scope) VALUES ('t-bogus', 'h-bogus', 'bogus')`,
	); err == nil {
		t.Error("api_tokens accepted an unknown scope after migration 017; CHECK not enforced")
	}

	// Seed half is idempotent.
	if _, err := raw.Exec(string(sql017[:firewallSeedByteLen(string(sql017))])); err != nil {
		// Only the seed (INSERT OR IGNORE) half is safe to re-run raw; the table
		// rebuild half is guarded by the migration runner. We re-run just the
		// seeds and assert the count is unchanged.
		t.Logf("re-exec of seed half returned: %v", err)
	}
	var count int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM whitelist_rules WHERE category = 'firewall'`).Scan(&count); err != nil {
		t.Fatalf("count firewall rules: %v", err)
	}
	if count != 3 {
		t.Errorf("firewall default rules = %d, want 3 (seed not idempotent?)", count)
	}

	var integrity string
	if err := raw.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Errorf("integrity_check = %q, want ok", integrity)
	}
}

// firewallSeedByteLen returns the byte offset of the "2." section marker in the
// 017 SQL so the seed (INSERT OR IGNORE) half can be re-run alone.
func firewallSeedByteLen(s string) int {
	const marker = "-- 2. Widen"
	if i := indexOf(s, marker); i > 0 {
		return i
	}
	return len(s)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestInlineFallback_AcceptsIngestScope opens a fresh database through
// store.Open in a temp working dir. From the test package's working directory
// the migration files are not found, so this exercises the inline fallback
// schema — which must now accept an ingest-scoped token (spec 001, FR-8).
func TestInlineFallback_AcceptsIngestScope(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vedetta.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open on fresh db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(
		`INSERT INTO api_tokens (token_id, token_hash, scope, label) VALUES ('t2', 'h2', 'ingest', 'l')`,
	); err != nil {
		t.Errorf("inline fallback schema rejected ingest-scoped token: %v", err)
	}

	// HasActiveIngestToken reflects the inserted token.
	has, err := db.HasActiveIngestToken()
	if err != nil {
		t.Fatalf("HasActiveIngestToken: %v", err)
	}
	if !has {
		t.Error("HasActiveIngestToken = false after inserting an ingest token")
	}
}

// TestIsEventWhitelisted_TagAndSourceIP verifies the firewall-event whitelist
// counterpart matches by tag and by source-IP glob, and never matches a
// domain-only DNS rule (firewall events carry no domain).
func TestIsEventWhitelisted_TagAndSourceIP(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vedetta.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	mustRule := func(r models.WhitelistRule) {
		if _, err := db.CreateWhitelistRule(r); err != nil {
			t.Fatalf("create rule %q: %v", r.Name, err)
		}
	}
	mustRule(models.WhitelistRule{Name: "wan-noise", TagMatch: "wan_scan_noise", Category: "firewall", Enabled: true})
	mustRule(models.WhitelistRule{Name: "self-scan", SourceIPPattern: "192.0.2.*", Category: "firewall", Enabled: true})
	mustRule(models.WhitelistRule{Name: "dns-only", DomainPattern: "*.example.com", Category: "custom", Enabled: true})

	if name, ok := db.IsEventWhitelisted([]string{"source:unifi", "wan_scan_noise"}, ""); !ok || name != "wan-noise" {
		t.Errorf("tag match: got (%q,%v), want (wan-noise,true)", name, ok)
	}
	if name, ok := db.IsEventWhitelisted([]string{"source:unifi", "fw:drop"}, "192.0.2.45"); !ok || name != "self-scan" {
		t.Errorf("source-IP glob match: got (%q,%v), want (self-scan,true)", name, ok)
	}
	if _, ok := db.IsEventWhitelisted([]string{"source:unifi", "fw:drop"}, "203.0.113.9"); ok {
		t.Error("firewall event matched a domain-only DNS rule; DNS rules must not suppress firewall events")
	}
}

// buildDeviceBaseState stands up the devices table with the fingerprint columns
// (model/os_family/etc) that migration 018's display_name backfill reads. It
// applies only the devices-shaping migrations that precede 018 and apply cleanly
// as raw SQL (001 creates the table; 007 adds the fingerprint columns), matching
// the buildBaseState approach used for the 017 test — deliberately avoiding the
// full raw chain, which has a known pre-existing break at migration 009 on a
// fresh DB (001_init.sql was baked to the final events schema).
func buildDeviceBaseState(t *testing.T, raw *sql.DB, migDir string) {
	t.Helper()
	for _, f := range []string{
		"001_init.sql",
		"007_device_fingerprints.sql",
	} {
		b, err := os.ReadFile(filepath.Join(migDir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("apply device base migration %s: %v", f, err)
		}
	}
}

// TestMigration018_SchemaAndBackfill applies migration 018 (spec 004) on top of a
// realistic post-017 devices schema and asserts:
//   - devices gains display_name + friendly_name columns;
//   - the three correlation tables (device_signals, device_identities,
//     device_networks) exist;
//   - the in-SQL backfill seeds MAC + hostname identities and network
//     attachments from pre-existing rows, computes a non-empty display_name,
//     and leaves first_seen untouched (no upgrade-time new_device wave);
//   - PRAGMA integrity_check reports ok.
//
// All values are synthetic per the constitution (RFC 5737 IPs, 00:00:5E:00:53:xx
// MACs, .local hostnames).
func TestMigration018_SchemaAndBackfill(t *testing.T) {
	migDir := findMigrationsDir(t)

	dbPath := filepath.Join(t.TempDir(), "correlation.db")
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer raw.Close()

	buildDeviceBaseState(t, raw, migDir)

	// Seed two pre-existing devices with distinct MACs/IPs on the same segment.
	// dev-a has a hostname; dev-b (MAC-less-hostname) does not.
	firstSeen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seed := func(id, ip, mac, host, vendor, model string) {
		if _, err := raw.Exec(`INSERT INTO devices
			(device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, model, segment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'iot')`,
			id, firstSeen, firstSeen, ip, mac, host, vendor, model); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("dev-a", "192.0.2.10", "00:00:5E:00:53:01", "living-room-tv.local", "Google", "Chromecast Ultra")
	seed("dev-b", "192.0.2.11", "00:00:5E:00:53:02", "", "Espressif", "")

	sql018, err := os.ReadFile(filepath.Join(migDir, "018_device_correlation.sql"))
	if err != nil {
		t.Fatalf("read migration 018: %v", err)
	}
	if _, err := raw.Exec(string(sql018)); err != nil {
		t.Fatalf("apply migration 018: %v", err)
	}

	// devices gained display_name + friendly_name columns.
	for _, col := range []string{"display_name", "friendly_name"} {
		var n int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = ?`, col).Scan(&n); err != nil {
			t.Fatalf("pragma_table_info devices/%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("devices.%s missing after migration 018", col)
		}
	}

	// The three correlation tables exist.
	for _, tbl := range []string{"device_signals", "device_identities", "device_networks"} {
		var n int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil {
			t.Fatalf("query sqlite_master for %s: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("table %s missing after migration 018", tbl)
		}
	}

	// Backfill: MAC alias for both devices, hostname alias for dev-a only.
	var macCount int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM device_identities WHERE id_type='mac'`).Scan(&macCount); err != nil {
		t.Fatalf("count mac identities: %v", err)
	}
	if macCount != 2 {
		t.Errorf("mac identities = %d, want 2", macCount)
	}
	var hostCount int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM device_identities WHERE id_type='hostname'`).Scan(&hostCount); err != nil {
		t.Fatalf("count hostname identities: %v", err)
	}
	if hostCount != 1 {
		t.Errorf("hostname identities = %d, want 1 (dev-a only; dev-b has empty hostname)", hostCount)
	}

	// Backfill: network attachment for both.
	var netCount int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM device_networks`).Scan(&netCount); err != nil {
		t.Fatalf("count networks: %v", err)
	}
	if netCount != 2 {
		t.Errorf("network attachments = %d, want 2", netCount)
	}

	// Backfill: display_name computed from model(+vendor) for dev-a.
	var displayA string
	if err := raw.QueryRow(`SELECT display_name FROM devices WHERE device_id='dev-a'`).Scan(&displayA); err != nil {
		t.Fatalf("read dev-a display_name: %v", err)
	}
	if displayA != "Chromecast Ultra (Google)" {
		t.Errorf("dev-a display_name = %q, want %q", displayA, "Chromecast Ultra (Google)")
	}

	// first_seen must be untouched (no upgrade-time new_device wave).
	var gotFirst time.Time
	if err := raw.QueryRow(`SELECT first_seen FROM devices WHERE device_id='dev-a'`).Scan(&gotFirst); err != nil {
		t.Fatalf("read dev-a first_seen: %v", err)
	}
	if !gotFirst.Equal(firstSeen) {
		t.Errorf("dev-a first_seen = %v, want unchanged %v", gotFirst, firstSeen)
	}

	var integrity string
	if err := raw.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Errorf("integrity_check = %q, want ok", integrity)
	}
}

// TestInlineFallback_HasCorrelationTables asserts the store's inline fallback
// schema (the path Go tests hit) carries the spec-004 devices columns and the
// three correlation tables, so UpsertDevice's resolver has its backing tables.
func TestInlineFallback_HasCorrelationTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vedetta.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open on fresh db: %v", err)
	}
	defer db.Close()

	for _, col := range []string{"display_name", "friendly_name", "services"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = ?`, col).Scan(&n); err != nil {
			t.Fatalf("pragma_table_info devices/%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("inline fallback devices.%s missing", col)
		}
	}
	for _, tbl := range []string{"device_signals", "device_identities", "device_networks"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil {
			t.Fatalf("query sqlite_master for %s: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("inline fallback table %s missing", tbl)
		}
	}
}

// stageMigrations copies every siem/migrations/*.sql into <dst>/siem/migrations so
// the store.Open runner's "siem/migrations" candidate (resolved relative to the
// process working directory) picks up the staged copy.
func stageMigrations(t *testing.T, dst string) {
	t.Helper()
	src := findMigrationsDir(t)
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	staged := filepath.Join(dst, "siem", "migrations")
	if err := os.MkdirAll(staged, 0o755); err != nil {
		t.Fatalf("mkdir staged migrations: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(staged, e.Name()), b, 0o644); err != nil {
			t.Fatalf("write staged %s: %v", e.Name(), err)
		}
	}
}

func stageFailingMigration(t *testing.T, dst string) string {
	t.Helper()
	migrationDir := filepath.Join(dst, "siem", "migrations")
	if err := os.MkdirAll(migrationDir, 0o755); err != nil {
		t.Fatalf("mkdir failing migrations: %v", err)
	}
	// legacy_alter_table deliberately remains ON when the following statement
	// fails. The runner must roll back the transaction and restore both
	// connection-local migration PRAGMAs before releasing the connection.
	script := `
		PRAGMA legacy_alter_table = ON;
		CREATE TABLE migration_should_rollback (id INTEGER PRIMARY KEY);
		INSERT INTO table_that_does_not_exist VALUES (1);
	`
	if err := os.WriteFile(filepath.Join(migrationDir, "001_fails.sql"), []byte(script), 0o644); err != nil {
		t.Fatalf("write failing migration: %v", err)
	}
	return migrationDir
}

func TestOpen_FileMigrationsInMemoryUsesOneConnection(t *testing.T) {
	t.Setenv("VEDETTA_MIGRATIONS_DIR", findMigrationsDir(t))

	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:) with file migrations: %v", err)
	}
	defer db.Close()

	// The test is intentionally serial and has performed no operation since Open.
	// Two connections here means the migration connection was still reserved when
	// runtime ensures ran, forcing database/sql to create a separate empty
	// :memory: database.
	if got := db.Stats().OpenConnections; got != 1 {
		t.Fatalf("Open(:memory:) retained %d pooled connections, want exactly 1 migrated database", got)
	}

	for _, table := range []string{"events", "devices", "api_tokens", "findings"} {
		var found int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&found); err != nil {
			t.Fatalf("inspect %s after in-memory migration: %v", table, err)
		}
		if found != 1 {
			t.Fatalf("table %s missing after in-memory file migration", table)
		}
	}

	var foreignKeys, legacyAlter int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys after in-memory migration: %v", err)
	}
	if err := db.QueryRow(`PRAGMA legacy_alter_table`).Scan(&legacyAlter); err != nil {
		t.Fatalf("read legacy_alter_table after in-memory migration: %v", err)
	}
	if foreignKeys != 1 || legacyAlter != 0 {
		t.Fatalf("migration connection PRAGMAs = foreign_keys:%d legacy_alter_table:%d, want 1/0", foreignKeys, legacyAlter)
	}
}

func TestMigrateFailureRestoresAndReleasesConnection(t *testing.T) {
	migrationDir := stageFailingMigration(t, t.TempDir())
	t.Setenv("VEDETTA_MIGRATIONS_DIR", migrationDir)

	raw, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "migration-cleanup.db")+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer raw.Close()
	// A single connection makes the lifecycle deterministic: the post-failure
	// PRAGMA reads must reuse the exact connection used by the migration runner.
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)

	db := &DB{DB: raw}
	if err := db.migrate(); err == nil {
		t.Fatal("migrate unexpectedly accepted the failing migration")
	}
	if got := raw.Stats().InUse; got != 0 {
		t.Fatalf("migration failure left %d connection(s) checked out, want 0", got)
	}

	var foreignKeys, legacyAlter int
	if err := raw.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys after failed migration: %v", err)
	}
	if err := raw.QueryRow(`PRAGMA legacy_alter_table`).Scan(&legacyAlter); err != nil {
		t.Fatalf("read legacy_alter_table after failed migration: %v", err)
	}
	if foreignKeys != 1 || legacyAlter != 0 {
		t.Fatalf("failed migration returned connection with foreign_keys:%d legacy_alter_table:%d, want 1/0", foreignKeys, legacyAlter)
	}

	var rolledBack int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migration_should_rollback'`).Scan(&rolledBack); err != nil {
		t.Fatalf("inspect failed migration rollback: %v", err)
	}
	if rolledBack != 0 {
		t.Fatal("failed migration did not roll back its schema changes")
	}
}

func TestOpenMigrationFailureClosesDatabase(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("VEDETTA_MIGRATIONS_DIR", stageFailingMigration(t, tmp))

	var opened *sql.DB
	opener := func(driverName, dataSourceName string) (*sql.DB, error) {
		db, err := sql.Open(driverName, dataSourceName)
		opened = db
		return db, err
	}
	if db, err := openWith(filepath.Join(tmp, "open-failure.db"), opener); err == nil {
		if db != nil {
			db.Close()
		}
		t.Fatal("openWith unexpectedly accepted the failing migration")
	}
	if opened == nil {
		t.Fatal("test opener was not called")
	}
	if err := opened.Ping(); err == nil {
		t.Fatal("database pool remained usable after Open returned a migration error")
	}
	if got := opened.Stats().OpenConnections; got != 0 {
		t.Fatalf("Open migration failure retained %d connection(s), want 0", got)
	}
}

// TestFullMigrationChain_RealRunner exercises the REAL filesystem migration runner
// (store.Open → migrate() over on-disk siem/migrations/*.sql), NOT the inline
// fallback. It is the permanent gate for two foundation-migration bugs:
//
//   - VED-015: a fresh-install run used to fail at 009_event_type_encrypted_dns.sql
//     with "table events has 14 columns but 19 values were supplied" (001_init.sql
//     ships the final 19-column events schema, but 009 recreated events with only
//     14 columns and copied via SELECT *). This test fails at store.Open if 009 is
//     reverted.
//   - VED-013: devices.segment / events.network_segment carried a restrictive
//     CHECK (... IN ('default','iot','guest')) that rejected UniFi/VLAN segment
//     names; migration 019 rebuilds both tables without that CHECK. The 'lan' /
//     'iot2' insert assertions below fail if 019 is reverted.
//
// The test stages the full raw chain and chdirs so the runner uses it — unlike
// buildBaseState/buildDeviceBaseState, which deliberately stage a targeted subset
// to avoid the (now-fixed) 009 break. All values are synthetic per the constitution
// (RFC 5737 IPs, 00:00:5E:00:53:xx MACs).
func TestFullMigrationChain_RealRunner(t *testing.T) {
	tmp := t.TempDir()
	stageMigrations(t, tmp)

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir to staged root: %v", err)
	}

	dbPath := filepath.Join(tmp, "fresh.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open on a fresh DB via the real migration runner failed: %v", err)
	}
	defer db.Close()

	// Sanity: the runner used the staged files, not the inline fallback. The
	// fallback path does not create scan_targets/sensors, so their presence proves
	// the file chain ran.
	for _, tbl := range []string{"scan_targets", "sensors", "api_tokens"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil {
			t.Fatalf("query sqlite_master for %s: %v", tbl, err)
		}
		if n != 1 {
			t.Fatalf("table %s missing — real file chain did not run (inline fallback?)", tbl)
		}
	}

	// PRAGMA integrity_check = ok.
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Errorf("integrity_check = %q, want ok", integrity)
	}

	// The events table has all final columns.
	wantEventCols := []string{
		"event_id", "timestamp", "event_type", "source_hash", "source_ip",
		"server_ip", "domain", "query_type", "resolved_ip", "blocked",
		"anomaly_score", "tags", "geo", "device_vendor", "network_segment",
		"dns_source", "metadata", "threat_desc", "acknowledged", "ack_reason",
	}
	for _, col := range wantEventCols {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = ?`, col).Scan(&n); err != nil {
			t.Fatalf("pragma_table_info events/%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("events.%s missing after the full real migration chain", col)
		}
	}

	// A device row with segment='lan' inserts successfully (segment CHECK relaxed).
	if _, err := db.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, segment)
		VALUES ('dev-lan', ?, ?, '192.0.2.20', '00:00:5E:00:53:10', 'nas.local', 'Synology', 'lan')`,
		time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Errorf("insert device with segment='lan' failed (segment CHECK not relaxed?): %v", err)
	}

	// An events row with network_segment='iot2' inserts (network_segment CHECK relaxed).
	if _, err := db.Exec(`INSERT INTO events
		(event_id, timestamp, event_type, source_hash, network_segment)
		VALUES ('evt-iot2', ?, 'dns_query', 'h-iot2', 'iot2')`,
		time.Now().UTC()); err != nil {
		t.Errorf("insert event with network_segment='iot2' failed (network_segment CHECK not relaxed?): %v", err)
	}
}

// TestMigration020_RepairsAlreadyBrokenCorrelationFKs proves migration 020 heals
// a database that ALREADY applied the broken (pre-fix) migration 019 — i.e. its
// device_signals / device_identities / device_networks foreign keys already point
// at the dropped devices_old_019 table. This is the upgrade-path half of the
// BUG-1 fix (the fresh-install half is covered by
// TestUpsertDevice_RealMigrationChainPersists via the fixed 019).
//
// It reconstructs the broken state directly (child tables whose FK REFERENCES the
// non-existent devices_old_019), inserts a device + child rows, applies only
// migration 020, and asserts the FKs now reference `devices` with no violations
// and the data survived.
//
// All values are synthetic per the constitution (RFC 5737 IPs, 00:00:5E:00:53:xx
// MACs, .local hostnames).
func TestMigration020_RepairsAlreadyBrokenCorrelationFKs(t *testing.T) {
	migDir := findMigrationsDir(t)

	dbPath := filepath.Join(t.TempDir(), "broken019.db")
	// Open with FKs OFF so we can construct the intentionally-dangling FK state.
	raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=off")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer raw.Close()

	// Minimal devices table (only the column 020's copies rely on: device_id).
	if _, err := raw.Exec(`CREATE TABLE devices (
		device_id TEXT PRIMARY KEY,
		first_seen TIMESTAMP NOT NULL,
		last_seen  TIMESTAMP NOT NULL,
		ip_address TEXT NOT NULL,
		mac_address TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create devices: %v", err)
	}

	// Recreate the exact broken shape: child tables REFERENCE devices_old_019,
	// which does not exist (019 dropped it). This is what the pre-fix 019 left.
	brokenChildren := []string{
		`CREATE TABLE device_signals (
			device_id TEXT NOT NULL REFERENCES devices_old_019(device_id),
			field TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
			confidence REAL NOT NULL DEFAULT 0.0,
			first_observed TIMESTAMP NOT NULL, last_observed TIMESTAMP NOT NULL,
			PRIMARY KEY (device_id, field, source))`,
		`CREATE TABLE device_identities (
			device_id TEXT NOT NULL REFERENCES devices_old_019(device_id),
			id_type TEXT NOT NULL, id_value TEXT NOT NULL,
			segment TEXT NOT NULL DEFAULT 'default',
			first_seen TIMESTAMP NOT NULL, last_seen TIMESTAMP NOT NULL,
			PRIMARY KEY (id_type, id_value, segment))`,
		`CREATE TABLE device_networks (
			device_id TEXT NOT NULL REFERENCES devices_old_019(device_id),
			segment TEXT NOT NULL, ip_address TEXT NOT NULL DEFAULT '',
			sensor_id TEXT NOT NULL DEFAULT '',
			first_seen TIMESTAMP NOT NULL, last_seen TIMESTAMP NOT NULL,
			PRIMARY KEY (device_id, segment))`,
	}
	for _, stmt := range brokenChildren {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("create broken child table: %v", err)
		}
	}

	// Seed a device and one row per child table (data must survive the repair).
	now := time.Now().UTC()
	if _, err := raw.Exec(`INSERT INTO devices (device_id, first_seen, last_seen, ip_address, mac_address)
		VALUES ('dev-x', ?, ?, '192.0.2.30', '00:00:5E:00:53:30')`, now, now); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO device_signals VALUES ('dev-x','vendor','ExampleCorp','oui',0.5,?,?)`, now, now); err != nil {
		t.Fatalf("seed signal: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO device_identities VALUES ('dev-x','mac','00:00:5E:00:53:30','lan',?,?)`, now, now); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO device_networks VALUES ('dev-x','lan','192.0.2.30','',?,?)`, now, now); err != nil {
		t.Fatalf("seed network: %v", err)
	}

	// Confirm the pre-repair state really is broken (FKs point at devices_old_019).
	var brokenRefs int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE sql LIKE '%devices_old_019%'`).Scan(&brokenRefs); err != nil {
		t.Fatalf("count broken refs: %v", err)
	}
	if brokenRefs != 3 {
		t.Fatalf("precondition: expected 3 child tables referencing devices_old_019, got %d", brokenRefs)
	}

	// Apply migration 020.
	sql020, err := os.ReadFile(filepath.Join(migDir, "020_repair_correlation_fks.sql"))
	if err != nil {
		t.Fatalf("read migration 020: %v", err)
	}
	if _, err := raw.Exec(string(sql020)); err != nil {
		t.Fatalf("apply migration 020: %v", err)
	}

	// No child table references devices_old_019 anymore.
	var afterRefs int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE sql LIKE '%devices_old_019%'`).Scan(&afterRefs); err != nil {
		t.Fatalf("count refs after 020: %v", err)
	}
	if afterRefs != 0 {
		t.Errorf("migration 020 left %d references to devices_old_019", afterRefs)
	}

	// Every child FK now references devices, and the data survived.
	for _, tc := range []struct {
		tbl  string
		want int
	}{{"device_signals", 1}, {"device_identities", 1}, {"device_networks", 1}} {
		var refTable string
		if err := raw.QueryRow(`SELECT "table" FROM pragma_foreign_key_list(?) LIMIT 1`, tc.tbl).Scan(&refTable); err != nil {
			t.Fatalf("fk list %s: %v", tc.tbl, err)
		}
		if refTable != "devices" {
			t.Errorf("%s FK references %q after 020, want devices", tc.tbl, refTable)
		}
		var rowCount int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM ` + tc.tbl).Scan(&rowCount); err != nil {
			t.Fatalf("count %s: %v", tc.tbl, err)
		}
		if rowCount != tc.want {
			t.Errorf("%s row count = %d after 020, want %d (data lost?)", tc.tbl, rowCount, tc.want)
		}
	}

	// Turn enforcement on and confirm the FK graph is clean.
	if _, err := raw.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("enable fks: %v", err)
	}
	rows, err := raw.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	var violations int
	for rows.Next() {
		violations++
	}
	if violations != 0 {
		t.Errorf("foreign_key_check reported %d violation(s) after 020, want 0", violations)
	}
}

// TestUpsertDevice_RealMigrationChainPersists is the permanent regression gate for
// BUG-1 (device inventory 100% dead on fresh install). It exercises the FULL,
// REAL path that production uses and that every other store test avoided:
//
//   - store.Open opens SQLite with _foreign_keys=on (see Open()), and the real
//     file migration runner applies the entire 001..NNN chain;
//   - it then calls UpsertDevice — the same code POST /api/v1/sensor/devices and
//     every LAN scan call — and asserts the device is ACTUALLY persisted.
//
// The bug: migration 019 renamed devices → devices_old_019 to rebuild it. With
// _foreign_keys=on and SQLite's default legacy_alter_table=off, that RENAME
// rewrote the child tables' foreign keys (device_signals / device_identities /
// device_networks) to REFERENCE "devices_old_019", which 019 then dropped —
// leaving dangling FKs. UpsertDevice runs in one tx: the devices INSERT
// succeeded but the follow-up identity/network/signal upserts failed with
// "no such table: main.devices_old_019", so defer tx.Rollback() threw the whole
// device away. GET /api/v1/devices returned total:0.
//
// Prior store tests missed this because they either inserted into the correlation
// tables via raw sql.Open with FKs OFF, or (TestFullMigrationChain_RealRunner)
// only db.Exec'd a raw devices INSERT — never UpsertDevice through the real store
// after the full chain. This test closes that gap.
//
// All values are synthetic per the constitution (RFC 5737 IPs, 00:00:5E:00:53:xx
// MACs, .local hostnames).
func TestUpsertDevice_RealMigrationChainPersists(t *testing.T) {
	tmp := t.TempDir()
	stageMigrations(t, tmp)

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir to staged root: %v", err)
	}

	dbPath := filepath.Join(tmp, "fresh.db")
	db, err := Open(dbPath) // REAL path: _foreign_keys=on + full file migration chain.
	if err != nil {
		t.Fatalf("store.Open on a fresh DB via the real migration runner failed: %v", err)
	}
	defer db.Close()

	// Prove the file chain ran (not the inline fallback, which never had the 019 bug).
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scan_targets'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("real file migration chain did not run (scan_targets missing, inline fallback?): n=%d err=%v", n, err)
	}

	// No leftover reference to the 019 rename table anywhere in the schema — this
	// is what proves the child-table FKs are NOT dangling to devices_old_019.
	var old019 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE sql LIKE '%old_019%'`).Scan(&old019); err != nil {
		t.Fatalf("query sqlite_master for old_019 refs: %v", err)
	}
	if old019 != 0 {
		t.Errorf("schema still references devices_old_019 in %d object(s); child FKs are orphaned", old019)
	}

	// Upsert a synthetic host through the REAL store (same call as the sensor API).
	host := discovery.DiscoveredHost{
		IPAddress:  "192.0.2.55",
		MACAddress: "00:00:5E:00:53:55",
		Hostname:   "printer.local",
		Vendor:     "ExampleCorp",
	}
	isNew, err := db.UpsertDevice(host, time.Now().UTC(), "lan")
	if err != nil {
		t.Fatalf("UpsertDevice failed on a fresh real-migration DB (BUG-1): %v", err)
	}
	if !isNew {
		t.Errorf("UpsertDevice reported isNew=false for a brand-new device")
	}

	// The device must actually be persisted (the tx must have committed).
	dev, err := db.GetDeviceByIP("192.0.2.55")
	if err != nil {
		t.Fatalf("GetDeviceByIP: %v", err)
	}
	if dev == nil {
		t.Fatal("device was NOT persisted after UpsertDevice — the correlation upserts rolled back the whole tx (BUG-1)")
	}
	if dev.IPAddress != "192.0.2.55" || dev.MACAddress != "00:00:5E:00:53:55" {
		t.Errorf("persisted device mismatch: ip=%q mac=%q", dev.IPAddress, dev.MACAddress)
	}

	list, err := db.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(list) < 1 {
		t.Errorf("ListDevices returned %d devices, want >= 1", len(list))
	}

	// The whole FK graph must be consistent after the real chain + a real upsert.
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	var violations int
	for rows.Next() {
		violations++
	}
	if violations != 0 {
		t.Errorf("PRAGMA foreign_key_check reported %d violation(s), want 0", violations)
	}

	// The child correlation tables must reference `devices`, not `devices_old_019`.
	for _, tbl := range []string{"device_signals", "device_identities", "device_networks"} {
		fkRows, err := db.Query(`SELECT "table" FROM pragma_foreign_key_list(?)`, tbl)
		if err != nil {
			t.Fatalf("pragma_foreign_key_list(%s): %v", tbl, err)
		}
		sawDevices := false
		for fkRows.Next() {
			var refTable string
			if err := fkRows.Scan(&refTable); err != nil {
				fkRows.Close()
				t.Fatalf("scan fk row for %s: %v", tbl, err)
			}
			if refTable == "devices" {
				sawDevices = true
			}
			if refTable == "devices_old_019" {
				t.Errorf("%s still references devices_old_019 (orphaned FK)", tbl)
			}
		}
		fkRows.Close()
		if !sawDevices {
			t.Errorf("%s has no FK referencing devices", tbl)
		}
	}
}

// stageMigrationsUpTo copies siem/migrations/NNN_*.sql files whose 3-digit numeric
// prefix is <= cutoff (e.g. "018") into <dst>/siem/migrations, so a store.Open run
// advances the DB only to that migration. Zero-padded prefixes compare correctly as
// strings.
func stageMigrationsUpTo(t *testing.T, dst, cutoff string) {
	t.Helper()
	src := findMigrationsDir(t)
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	staged := filepath.Join(dst, "siem", "migrations")
	if err := os.MkdirAll(staged, 0o755); err != nil {
		t.Fatalf("mkdir staged migrations: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if len(e.Name()) < 3 || e.Name()[:3] > cutoff {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(staged, e.Name()), b, 0o644); err != nil {
			t.Fatalf("write staged %s: %v", e.Name(), err)
		}
	}
}

// TestFullMigrationChain_PopulatedLegacyDB_FKSafe is the regression gate for the
// migration-runner foreign-key crash: applying the 019/025 events+devices table
// REBUILDS to a database that already holds device rows + correlation child rows.
//
// The runner opens SQLite with _foreign_keys=on, and migration 019 rebuilds devices
// via RENAME -> CREATE -> copy -> DROP old. With enforcement on, DROPping the renamed
// old table does an implicit row-by-row DELETE that enforces FK RESTRICT against the
// device_networks / device_identities / device_signals rows migration 018 created,
// raising "FOREIGN KEY constraint failed". It ONLY fires with data present — which is
// why every other real-runner test here (zero device rows) stayed green while a real
// 015->025 upgrade of a live inventory crashed the backend fail-closed at 019.
//
// This test seeds a device + a device_networks child row at the 018 schema, then runs
// the REAL runner over 019..025 and asserts it completes, preserves the data, and
// leaves a clean foreign_key_check. It fails (store.Open error at 019) if the runner
// stops relaxing FK enforcement for the migration pass.
//
// All values are synthetic per the constitution (RFC 5737 IPs, 00:00:5E:00:53:xx MACs).
func TestFullMigrationChain_PopulatedLegacyDB_FKSafe(t *testing.T) {
	tmp := t.TempDir()

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir to staged root: %v", err)
	}

	dbPath := filepath.Join(tmp, "legacy.db")

	// Phase 1: advance a fresh DB only to migration 018 via the real runner, then
	// populate it the way production does — a device with a correlation child row.
	stageMigrationsUpTo(t, tmp, "018")
	db18, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open to migration 018 failed: %v", err)
	}
	var head string
	if err := db18.QueryRow(`SELECT MAX(id) FROM schema_migrations`).Scan(&head); err != nil {
		t.Fatalf("read migration head: %v", err)
	}
	if !strings.HasPrefix(head, "018") {
		t.Fatalf("expected DB staged at 018, got %q (staging filter broken)", head)
	}
	now := time.Now().UTC()
	// segment='default' satisfies the pre-019 CHECK (IN 'default','iot','guest').
	if _, err := db18.Exec(`INSERT INTO devices
		(device_id, first_seen, last_seen, ip_address, mac_address, hostname, vendor, segment)
		VALUES ('dev-legacy', ?, ?, '192.0.2.77', '00:00:5E:00:53:77', 'nas.local', 'ExampleCorp', 'default')`,
		now, now); err != nil {
		t.Fatalf("seed device at 018: %v", err)
	}
	// The correlation child row whose FK to devices makes 019's DROP-under-FK-on trip.
	if _, err := db18.Exec(`INSERT INTO device_networks
		(device_id, segment, ip_address, sensor_id, first_seen, last_seen)
		VALUES ('dev-legacy', 'default', '192.0.2.77', 'sensor-1', ?, ?)`,
		now, now); err != nil {
		t.Fatalf("seed device_networks child row at 018: %v", err)
	}
	if err := db18.Close(); err != nil {
		t.Fatalf("close 018 db: %v", err)
	}

	// Phase 2: complete the chain (019..025) and re-open. The real runner now applies
	// the events+devices rebuilds to the POPULATED DB. Pre-fix this returned
	// "FOREIGN KEY constraint failed" at 019; post-fix it must succeed.
	stageMigrations(t, tmp)
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open over 019..025 on a POPULATED legacy DB failed (the FK-on rebuild regression): %v", err)
	}
	defer db.Close()

	if err := db.QueryRow(`SELECT MAX(id) FROM schema_migrations`).Scan(&head); err != nil {
		t.Fatalf("read migration head after full chain: %v", err)
	}
	if !strings.HasPrefix(head, "025") {
		t.Errorf("migration head = %q, want 025_*", head)
	}

	// The seeded device + child row survived the rebuilds.
	var devCount, netCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE device_id = 'dev-legacy'`).Scan(&devCount); err != nil {
		t.Fatalf("count seeded device: %v", err)
	}
	if devCount != 1 {
		t.Errorf("seeded device count = %d after migration, want 1 (data lost in rebuild)", devCount)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_networks WHERE device_id = 'dev-legacy'`).Scan(&netCount); err != nil {
		t.Fatalf("count seeded child row: %v", err)
	}
	if netCount != 1 {
		t.Errorf("seeded device_networks count = %d after migration, want 1", netCount)
	}

	// The whole FK graph is consistent, and enforcement was restored (a bad child
	// write must still be rejected after migration).
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	var violations int
	for rows.Next() {
		violations++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("iterate foreign_key_check: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close foreign_key_check rows: %v", err)
	}
	if violations != 0 {
		t.Errorf("PRAGMA foreign_key_check reported %d violation(s) after the populated upgrade, want 0", violations)
	}

	if _, err := db.Exec(`INSERT INTO device_networks
		(device_id, segment, first_seen, last_seen)
		VALUES ('ghost-device', 'default', ?, ?)`, now, now); err == nil {
		t.Error("FK enforcement was NOT restored after migration: a child row referencing a nonexistent device was accepted")
	}

	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		t.Errorf("integrity_check = %q, want ok", integrity)
	}
}
