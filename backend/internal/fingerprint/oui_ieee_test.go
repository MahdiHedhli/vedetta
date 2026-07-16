package fingerprint

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func resetManagedOUIState(t *testing.T) {
	t.Helper()
	managedOUIPath.Store(nil)
	ieeeOUIMu.Lock()
	ieeeOUI = nil
	ieeeOUIMu.Unlock()
	t.Cleanup(func() {
		managedOUIPath.Store(nil)
		ieeeOUIMu.Lock()
		ieeeOUI = nil
		ieeeOUIMu.Unlock()
	})
}

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
	resetManagedOUIState(t)
	t.Setenv(ouiDBOverrideEnv, "")
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
	if err := os.WriteFile(good, embeddedOUICSV, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := loadOUICSVFile(good)
	if err != nil || len(m) < minimumFullOUIRows {
		t.Fatalf("valid full override: rows=%d err=%v", len(m), err)
	}

	// A syntactically valid but partial override is rejected, so it cannot silently
	// erase almost all of the embedded registry's coverage.
	partial := filepath.Join(dir, "partial.csv")
	if err := os.WriteFile(partial, []byte("prefix,vendor\naabbcc,Override Vendor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOUICSVFile(partial); err == nil {
		t.Error("expected an error for a partial override")
	}

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
	resetManagedOUIState(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.csv")
	override := bytes.Replace(embeddedOUICSV, []byte("000000,XEROX CORPORATION"), []byte("000000,Env Override Co"), 1)
	if bytes.Equal(override, embeddedOUICSV) {
		t.Fatal("test fixture did not replace the baseline vendor")
	}
	if err := os.WriteFile(p, override, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ouiDBOverrideEnv, p)
	m := loadIEEEOUI()
	if m["000000"] != "Env Override Co" {
		t.Fatalf("env override not applied: got %q", m["000000"])
	}
	if len(m) < minimumFullOUIRows {
		t.Errorf("a valid override should retain a full registry, got %d rows", len(m))
	}
}

func TestLoadIEEEOUI_PartialOverrideFallsBack(t *testing.T) {
	resetManagedOUIState(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.csv")
	if err := os.WriteFile(p, []byte("prefix,vendor\naabbcc,Partial Override\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ouiDBOverrideEnv, p)
	m := loadIEEEOUI()
	if len(m) < minimumFullOUIRows {
		t.Fatalf("partial override replaced the embedded baseline: got %d rows", len(m))
	}
	if v := m["000000"]; !strings.Contains(v, "XEROX") {
		t.Fatalf("embedded fallback was not retained: 000000=%q", v)
	}
}

func TestReloadIEEEOUI_AtomicallyPublishesOverride(t *testing.T) {
	resetManagedOUIState(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "oui.csv")
	override := bytes.Replace(embeddedOUICSV, []byte("000000,XEROX CORPORATION"), []byte("000000,Reloaded Vendor"), 1)
	if bytes.Equal(override, embeddedOUICSV) {
		t.Fatal("test fixture did not replace the baseline vendor")
	}
	if err := os.WriteFile(path, override, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ouiDBOverrideEnv, path)
	if err := ReloadIEEEOUI(); err != nil {
		t.Fatal(err)
	}
	if got := (&Engine{}).Lookup("00:00:00:00:00:01"); got == nil || got.Vendor != "Reloaded Vendor" {
		t.Fatalf("lookup did not see reloaded generation: %#v", got)
	}

	// Repeated publication while readers are active exercises the immutable map swap under
	// the race detector; no reader should observe a partial map or data race.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = (&Engine{}).Lookup("00:00:00:00:00:01")
			}
		}()
	}
	for i := 0; i < 3; i++ {
		if err := ReloadIEEEOUI(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()

	t.Setenv(ouiDBOverrideEnv, "")
	if err := ReloadIEEEOUI(); err != nil {
		t.Fatalf("restore embedded index: %v", err)
	}
}

func TestEnableManagedIEEEOUIRequiresProcessLocalActivation(t *testing.T) {
	resetManagedOUIState(t)
	dir := t.TempDir()
	managedPath := filepath.Join(dir, "oui.csv")
	managed := bytes.Replace(embeddedOUICSV, []byte("000000,XEROX CORPORATION"), []byte("000000,Managed Update Vendor"), 1)
	if bytes.Equal(managed, embeddedOUICSV) {
		t.Fatal("test fixture did not replace the baseline vendor")
	}
	if err := os.WriteFile(managedPath, managed, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(ouiDBOverrideEnv, "")
	if err := ReloadIEEEOUI(); err != nil {
		t.Fatal(err)
	}
	if got := (&Engine{}).Lookup("00:00:00:00:00:01"); got == nil || !strings.Contains(got.Vendor, "XEROX") {
		t.Fatalf("managed file became active before validated activation: %#v", got)
	}
	if err := EnableManagedIEEEOUI(dir); err != nil {
		t.Fatal(err)
	}
	if got := (&Engine{}).Lookup("00:00:00:00:00:01"); got == nil || got.Vendor != "Managed Update Vendor" {
		t.Fatalf("validated managed generation not loaded: %#v", got)
	}

	// A fresh process with the updater disabled has no activation authority even though
	// the downloaded generation deliberately remains on disk.
	managedOUIPath.Store(nil)
	if err := ReloadIEEEOUI(); err != nil {
		t.Fatal(err)
	}
	if got := (&Engine{}).Lookup("00:00:00:00:00:01"); got == nil || !strings.Contains(got.Vendor, "XEROX") {
		t.Fatalf("disabled updater did not restore embedded baseline: %#v", got)
	}
}

func TestEnableManagedIEEEOUIRejectsUnusableExistingGeneration(t *testing.T) {
	resetManagedOUIState(t)
	dir := t.TempDir()
	t.Setenv(ouiDBOverrideEnv, "")
	if err := EnableManagedIEEEOUI(dir); err == nil {
		t.Fatal("expected an existing empty install directory to fail activation")
	}
	if err := os.WriteFile(filepath.Join(dir, "oui.csv"), []byte("prefix,vendor\naabbcc,Partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnableManagedIEEEOUI(dir); err == nil {
		t.Fatal("expected unusable managed generation to fail activation")
	}
	if managedOUIPath.Load() != nil {
		t.Fatal("failed activation retained managed-source authority")
	}
	if err := ReloadIEEEOUI(); err != nil {
		t.Fatal(err)
	}
	if got := (&Engine{}).Lookup("00:00:00:00:00:01"); got == nil || !strings.Contains(got.Vendor, "XEROX") {
		t.Fatalf("failed activation did not retain embedded baseline: %#v", got)
	}
}
