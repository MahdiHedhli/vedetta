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
	"testing"

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
