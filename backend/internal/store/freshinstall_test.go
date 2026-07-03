package store

// Permanent regression tests for fresh installs.
//
// These guard against two failure modes that shipped (and were caught) during
// development:
//  1. Editing an already-shipped migration (001) to include columns that later
//     migrations ALTER-add, breaking fresh installs with "duplicate column name".
//  2. The inline fallback schema (used when migration files are absent — the
//     path go tests hit) drifting behind what the store code reads/writes
//     ("no such column: eol_risk" in ListDevices).

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// TestFreshInstall_RealMigrationChain applies every migration file in order on
// a brand-new database, exactly like a fresh production install would.
// It fails if any migration errors (e.g. duplicate column, missing table).
func TestFreshInstall_RealMigrationChain(t *testing.T) {
	migDir := findMigrationsDir(t)

	entries, err := os.ReadDir(migDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("no migration files found")
	}

	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite db: %v", err)
	}
	defer raw.Close()

	for _, name := range files {
		sqlBytes, err := os.ReadFile(filepath.Join(migDir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if _, err := raw.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("migration %s failed on fresh install: %v", name, err)
		}
	}

	// Sanity: the columns the store code depends on must exist after the chain.
	for _, check := range []struct{ table, column string }{
		{"events", "server_ip"},
		{"events", "source_ip"},
		{"events", "dns_source"},
		{"events", "metadata"},
		{"events", "acknowledged"},
		{"devices", "services"},
		{"devices", "eol_risk"},
		{"devices", "risk_category"},
		{"devices", "risk_reasons"},
	} {
		var n int
		err := raw.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`,
			check.table, check.column).Scan(&n)
		if err != nil {
			t.Fatalf("pragma_table_info(%s): %v", check.table, err)
		}
		if n == 0 {
			t.Errorf("column %s.%s missing after full migration chain", check.table, check.column)
		}
	}
}

// TestFreshInstall_StoreOpenAndCRUD opens a fresh database through store.Open
// in a temp dir (from the test package's working directory the migration files
// are not found, so this exercises the inline fallback schema) and runs the
// core store operations end-to-end.
func TestFreshInstall_StoreOpenAndCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vedetta.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open on fresh db: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()

	// InsertEvents with a representative sensor event.
	events := []models.Event{{
		EventID:        "test-event-1",
		Timestamp:      now,
		EventType:      "dns_query",
		SourceHash:     "abc123",
		SourceIP:       "192.168.1.50",
		ServerIP:       "192.168.1.1",
		Domain:         "example.com",
		QueryType:      "A",
		ResolvedIP:     "93.184.216.34",
		AnomalyScore:   0.1,
		Tags:           []string{"test"},
		NetworkSegment: "default",
		DNSSource:      "passive_capture",
		Metadata:       `{"test":true}`,
	}}
	inserted, err := db.InsertEvents(events)
	if err != nil {
		t.Fatalf("InsertEvents on fresh db: %v", err)
	}
	if inserted != 1 {
		t.Fatalf("InsertEvents inserted %d events, want 1", inserted)
	}

	// QueryEvents must scan the inserted row without column errors.
	res, err := db.QueryEvents(EventQueryParams{})
	if err != nil {
		t.Fatalf("QueryEvents on fresh db: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("QueryEvents total = %d, want 1", res.Total)
	}

	// UpsertDevice with a representative discovered host.
	host := discovery.DiscoveredHost{
		IPAddress:       "192.168.1.50",
		MACAddress:      "aa:bb:cc:dd:ee:ff",
		Hostname:        "test-host.local",
		Vendor:          "TestVendor",
		OpenPorts:       []int{22, 80},
		Status:          "up",
		Model:           "TestModel 3000",
		Services:        []string{"_http._tcp", "_ssh._tcp"},
		DiscoverySource: "passive_mdns",
	}
	isNew, err := db.UpsertDevice(host, now)
	if err != nil {
		t.Fatalf("UpsertDevice (insert) on fresh db: %v", err)
	}
	if !isNew {
		t.Fatal("UpsertDevice should report a new device on fresh db")
	}

	// Second upsert exercises the UPDATE paths.
	if _, err := db.UpsertDevice(host, now.Add(time.Minute)); err != nil {
		t.Fatalf("UpsertDevice (update) on fresh db: %v", err)
	}

	// ListDevices must scan every selected column into a destination.
	devices, err := db.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices on fresh db: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("ListDevices returned %d devices, want 1", len(devices))
	}
	if got := devices[0].Services; len(got) != 2 {
		t.Errorf("ListDevices services = %v, want 2 entries", got)
	}

	// GetDeviceByIP likewise.
	dev, err := db.GetDeviceByIP("192.168.1.50")
	if err != nil {
		t.Fatalf("GetDeviceByIP on fresh db: %v", err)
	}
	if dev == nil {
		t.Fatal("GetDeviceByIP returned nil for existing device")
	}
	if len(dev.Services) != 2 {
		t.Errorf("GetDeviceByIP services = %v, want 2 entries", dev.Services)
	}

	// GetNewDevices exercises the third device scan path.
	if _, err := db.GetNewDevices(24 * time.Hour); err != nil {
		t.Fatalf("GetNewDevices on fresh db: %v", err)
	}
}
