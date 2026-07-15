package fingerprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOUICSV(t *testing.T) {
	const data = `prefix,vendor
000393,"Apple, Inc."
ACBC32,"Apple, Inc."
0000fb,Some Vendor
zzzzzz,Bad Prefix
0011,Too Short
,Missing Prefix
00abcd,`
	got := parseOUICSV(strings.NewReader(data))
	want := map[string]string{
		"000393": "Apple, Inc.", // vendor with a comma (CSV-quoted) preserved
		"acbc32": "Apple, Inc.", // uppercase prefix normalized to lowercase
		"0000fb": "Some Vendor",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows %v, want %d (header/short/non-hex/empty must drop)", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("prefix %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestLoadIEEEOUI_EmbeddedBaseline(t *testing.T) {
	m := loadIEEEOUI()
	if len(m) < 30000 {
		t.Fatalf("embedded IEEE OUI table too small: %d rows", len(m))
	}
	if v, ok := m["acbc32"]; !ok || !strings.Contains(v, "Apple") {
		t.Errorf("expected an Apple vendor for acbc32, got %q (ok=%v)", v, ok)
	}
}

func TestLoadOUICSVFile_OverrideAndReject(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "oui.csv")
	if err := os.WriteFile(good, []byte("prefix,vendor\naabbcc,Override Vendor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := loadOUICSVFile(good)
	if err != nil || m["aabbcc"] != "Override Vendor" {
		t.Fatalf("valid override: m=%v err=%v", m, err)
	}

	// An override with no usable rows is rejected, so it can't wipe the baseline.
	empty := filepath.Join(dir, "empty.csv")
	if err := os.WriteFile(empty, []byte("prefix,vendor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOUICSVFile(empty); err == nil {
		t.Error("expected an error for an override with no usable rows")
	}
	if _, err := loadOUICSVFile(filepath.Join(dir, "missing.csv")); err == nil {
		t.Error("expected an error for a missing override file")
	}
}

func TestLoadIEEEOUI_EnvOverrideReplacesBaseline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.csv")
	if err := os.WriteFile(p, []byte("prefix,vendor\n001122,Env Override Co\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ouiDBOverrideEnv, p)
	m := loadIEEEOUI()
	if m["001122"] != "Env Override Co" {
		t.Fatalf("env override not applied: got %q", m["001122"])
	}
	if len(m) != 1 {
		t.Errorf("a valid override should fully replace the baseline, got %d rows", len(m))
	}
}
