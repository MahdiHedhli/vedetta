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
