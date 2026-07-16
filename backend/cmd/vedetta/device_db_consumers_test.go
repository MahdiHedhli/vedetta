package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/fingerprint"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func TestActivateDeviceDBConsumersRejectsCorpusBeforePublishingOUI(t *testing.T) {
	t.Setenv("VEDETTA_OUI_DB_PATH", "")
	engine := &fingerprint.Engine{}
	before := engine.Lookup("00:00:00:00:00:01")
	if before == nil {
		t.Fatal("embedded OUI baseline lookup is missing")
	}

	embedded, err := os.ReadFile(filepath.Join("..", "..", "internal", "fingerprint", "data", "oui.csv"))
	if err != nil {
		t.Fatal(err)
	}
	staged := bytes.Replace(embedded, []byte("000000,XEROX CORPORATION"), []byte("000000,Must Not Publish"), 1)
	if bytes.Equal(staged, embedded) {
		t.Fatal("test fixture did not replace the baseline vendor")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oui.csv"), staged, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corpus.json"), []byte(`{"schema_version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := activateDeviceDBConsumers(db, dir); err == nil {
		t.Fatal("activation accepted an invalid corpus")
	}
	after := engine.Lookup("00:00:00:00:00:01")
	if after == nil || after.Vendor != before.Vendor {
		t.Fatalf("failed corpus preparation partially published OUI: before=%#v after=%#v", before, after)
	}
}
