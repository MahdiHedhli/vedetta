package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestReactivatedSensorRequestedAsPrimaryIsTheOnlyActivePrimary(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "reactivate-primary.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	primary := models.Sensor{
		SensorID: "sensor-primary", Hostname: "primary", OS: "linux", Arch: "amd64",
		CIDR: "192.0.2.0/24", Version: "test",
	}
	returning := models.Sensor{
		SensorID: "sensor-returning", Hostname: "returning", OS: "linux", Arch: "arm64",
		CIDR: "198.51.100.0/24", Version: "test",
	}
	if err := db.RegisterSensor(primary); err != nil {
		t.Fatalf("register initial primary: %v", err)
	}
	_, initialToken, err := auth.GenerateToken(auth.ScopeSensor, returning.SensorID, "initial")
	if err != nil {
		t.Fatalf("generate initial sensor token: %v", err)
	}
	if err := db.ProvisionSensorToken(returning, initialToken, false); err != nil {
		t.Fatalf("provision returning sensor: %v", err)
	}
	if err := db.SetPrimarySensor(primary.SensorID); err != nil {
		t.Fatalf("restore initial primary: %v", err)
	}
	if _, err := db.RemoveSensor(returning.SensorID, "admin-test", "retired"); err != nil {
		t.Fatalf("remove non-primary sensor: %v", err)
	}

	returning.IsPrimary = true
	_, resetToken, err := auth.GenerateToken(auth.ScopeSensor, returning.SensorID, "reactivation")
	if err != nil {
		t.Fatalf("generate reactivation token: %v", err)
	}
	if err := db.ProvisionSensorTokenWithActor(returning, resetToken, true, "admin-test"); err != nil {
		t.Fatalf("reactivate sensor as primary: %v", err)
	}

	var activePrimaries int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM sensors
		WHERE removed_at IS NULL AND is_primary = TRUE
	`).Scan(&activePrimaries); err != nil {
		t.Fatalf("count active primaries: %v", err)
	}
	if activePrimaries != 1 {
		t.Fatalf("active primary count = %d, want 1", activePrimaries)
	}

	got, err := db.GetPrimarySensor()
	if err != nil {
		t.Fatalf("get primary sensor: %v", err)
	}
	if got.SensorID != returning.SensorID {
		t.Fatalf("primary sensor = %q, want %q", got.SensorID, returning.SensorID)
	}

	var oldPrimary bool
	if err := db.QueryRow(`SELECT is_primary FROM sensors WHERE sensor_id = ?`, primary.SensorID).Scan(&oldPrimary); err != nil {
		t.Fatalf("read former primary: %v", err)
	}
	if oldPrimary {
		t.Fatal("reactivation left the former primary marked primary")
	}
}

func TestCreateTokenRejectsSensorScopeRegardlessOfBinding(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "generic-sensor-token.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	for _, sensorID := range []string{"", "sensor-bound"} {
		name := "without-sensor-id"
		if sensorID != "" {
			name = "with-sensor-id"
		}
		t.Run(name, func(t *testing.T) {
			_, token, err := auth.GenerateToken(auth.ScopeSensor, sensorID, "must-use-enrollment")
			if err != nil {
				t.Fatalf("generate token: %v", err)
			}
			if err := db.CreateToken(token); err == nil {
				t.Fatal("CreateToken accepted a sensor-scoped token")
			}
		})
	}

	var sensorTokens int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE scope = ?`, auth.ScopeSensor).Scan(&sensorTokens); err != nil {
		t.Fatalf("count sensor tokens: %v", err)
	}
	if sensorTokens != 0 {
		t.Fatalf("generic creation persisted %d sensor tokens, want 0", sensorTokens)
	}
}

func TestPre026DatabaseUpgradesThroughInlineFallback(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pre-026.db")

	// This is the exact sensor table shape immediately before migration 026.
	// Seed data as well: the fallback must upgrade, not merely create a fresh DB.
	raw, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE sensors (
			sensor_id  TEXT PRIMARY KEY,
			hostname   TEXT NOT NULL,
			os         TEXT NOT NULL,
			arch       TEXT NOT NULL,
			cidr       TEXT NOT NULL,
			version    TEXT NOT NULL,
			first_seen TIMESTAMP NOT NULL,
			last_seen  TIMESTAMP NOT NULL,
			status     TEXT NOT NULL DEFAULT 'online',
			is_primary BOOLEAN NOT NULL DEFAULT FALSE,
			interfaces TEXT DEFAULT '[]'
		);
		INSERT INTO sensors
			(sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary)
		VALUES
			('legacy-sensor', 'legacy', 'linux', 'amd64', '203.0.113.0/24', 'beta',
			 CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'online', TRUE);
	`); err != nil {
		raw.Close()
		t.Fatalf("create pre-026 schema: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// An existing but empty directory takes precedence over source-tree
	// migrations and forces the binary-only inline fallback path.
	emptyMigrations := filepath.Join(tmp, "no-migration-files")
	if err := os.Mkdir(emptyMigrations, 0o755); err != nil {
		t.Fatalf("create empty migrations directory: %v", err)
	}
	t.Setenv("VEDETTA_MIGRATIONS_DIR", emptyMigrations)

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open pre-026 database via inline fallback: %v", err)
	}
	defer db.Close()

	for _, column := range []string{"removed_at", "removed_by_token_id", "removal_reason"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name = ?`, column).Scan(&count); err != nil {
			t.Fatalf("inspect sensors.%s: %v", column, err)
		}
		if count != 1 {
			t.Errorf("sensors.%s count = %d, want 1", column, count)
		}
	}

	var lifecycleTables int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'table' AND name = 'sensor_lifecycle_events'
	`).Scan(&lifecycleTables); err != nil {
		t.Fatalf("inspect sensor_lifecycle_events: %v", err)
	}
	if lifecycleTables != 1 {
		t.Fatalf("sensor_lifecycle_events count = %d, want 1", lifecycleTables)
	}

	active, err := db.SensorActive("legacy-sensor")
	if err != nil {
		t.Fatalf("check upgraded legacy sensor: %v", err)
	}
	if !active {
		t.Fatal("inline upgrade did not preserve the existing sensor as active")
	}
}

func TestAuthenticatedSensorRefreshElectsPrimaryAtomically(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "refresh-primary.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	primary := models.Sensor{
		SensorID: "refresh-primary", Hostname: "primary", OS: "linux", Arch: "amd64",
		CIDR: "192.0.2.0/24", Version: "test",
	}
	candidate := models.Sensor{
		SensorID: "refresh-candidate", Hostname: "candidate", OS: "linux", Arch: "arm64",
		CIDR: "198.51.100.0/24", Version: "test",
	}
	if err := db.RegisterSensor(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	_, token, err := auth.GenerateToken(auth.ScopeSensor, candidate.SensorID, "refresh")
	if err != nil {
		t.Fatalf("generate candidate token: %v", err)
	}
	if err := db.ProvisionSensorToken(candidate, token, false); err != nil {
		t.Fatalf("provision candidate: %v", err)
	}

	assertOnlyPrimary := func(want string) {
		t.Helper()
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE removed_at IS NULL AND is_primary = TRUE`).Scan(&count); err != nil {
			t.Fatalf("count primaries: %v", err)
		}
		got, err := db.GetPrimarySensor()
		if err != nil {
			t.Fatalf("get primary: %v", err)
		}
		if count != 1 || got.SensorID != want {
			t.Fatalf("primary state: count=%d id=%q, want 1/%q", count, got.SensorID, want)
		}
	}

	// An authenticated steady-state registration must honor the existing
	// --primary client contract without the old demote-only zero-primary bug.
	candidate.IsPrimary = true
	if err := db.RefreshSensorWithActiveToken(candidate, token.TokenID); err != nil {
		t.Fatalf("refresh candidate as primary: %v", err)
	}
	assertOnlyPrimary(candidate.SensorID)

	// It also self-heals an old/corrupt database with no active primary even when
	// the registering sensor did not explicitly request election.
	if _, err := db.Exec(`UPDATE sensors SET is_primary = FALSE`); err != nil {
		t.Fatalf("clear primary flags: %v", err)
	}
	candidate.IsPrimary = false
	if err := db.RefreshSensorWithActiveToken(candidate, token.TokenID); err != nil {
		t.Fatalf("refresh into zero-primary fleet: %v", err)
	}
	assertOnlyPrimary(candidate.SensorID)
}

func TestMakeCleanTokensPreservesSensorIdentity(t *testing.T) {
	repoRoot := filepath.Dir(filepath.Dir(findMigrationsDir(t)))
	contents, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	source := string(contents)
	start := strings.Index(source, "\nclean-tokens:")
	if start < 0 {
		t.Fatal("Makefile clean-tokens target not found")
	}
	section := source[start:]
	if end := strings.Index(section, "\n# --- Simulation"); end >= 0 {
		section = section[:end]
	}
	for _, destructive := range []string{"DELETE FROM sensors", "DELETE FROM api_tokens"} {
		if strings.Contains(section, destructive) {
			t.Fatalf("clean-tokens destroys retained identity state: found %q", destructive)
		}
	}
	if !strings.Contains(section, "UPDATE api_tokens SET revoked = 1") {
		t.Fatal("clean-tokens no longer revokes sensor credentials")
	}
}
