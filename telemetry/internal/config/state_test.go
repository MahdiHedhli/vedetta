package config

import (
	"os"
	"path/filepath"
	"testing"
)

type sample struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "file.json")
	in := sample{Version: StateFileVersion, Value: "hello"}
	if err := WriteJSONFile(p, in, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out sample
	found, err := ReadJSONFile(p, &out)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if out != in {
		t.Errorf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestReadMissing(t *testing.T) {
	var out sample
	found, err := ReadJSONFile(filepath.Join(t.TempDir(), "nope.json"), &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if found {
		t.Errorf("expected not found")
	}
}

func TestReadCorruptRegenerates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(p, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out sample
	found, err := ReadJSONFile(p, &out)
	if err != nil {
		t.Fatalf("corrupt should not error: %v", err)
	}
	if found {
		t.Errorf("corrupt file should report not found so caller regenerates")
	}
}

func TestPermissionBits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.json")
	if err := WriteJSONFile(p, sample{Version: 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteSecretBytesPerm(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "salt")
	if err := WriteSecretBytes(p, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("salt perm = %v, want 0600", info.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	if len(b) != 4 {
		t.Errorf("salt bytes = %d", len(b))
	}
}

func TestCheckVersion(t *testing.T) {
	if err := CheckVersion("x", StateFileVersion); err != nil {
		t.Errorf("current version should pass: %v", err)
	}
	if err := CheckVersion("x", StateFileVersion+1); err == nil {
		t.Errorf("newer version should fail")
	}
}
