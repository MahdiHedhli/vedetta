package export

import (
	"os"
	"path/filepath"
	"testing"
)

// fixturesDir locates the shared contract fixtures consumed by both this
// service and specs/003-threat-network's validator.
func fixturesDir(t *testing.T) string {
	t.Helper()
	// telemetry/internal/export → repo root is ../../.. then into specs.
	dir := filepath.Join("..", "..", "..", "specs", "002-telemetry-service", "contracts", "fixtures")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("fixtures dir not found: %v", err)
	}
	return dir
}

func TestSharedFixtureValidBatchIsLeakFree(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesDir(t), "batch-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v := LeakScan(data); len(v) > 0 {
		t.Errorf("shared valid fixture has leaks: %v", v)
	}
}

func TestSharedFixtureForbiddenBatchIsCaught(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesDir(t), "batch-forbidden-ip.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v := LeakScan(data); len(v) == 0 {
		t.Errorf("forbidden-ip fixture should be flagged by leak scan")
	}
}
