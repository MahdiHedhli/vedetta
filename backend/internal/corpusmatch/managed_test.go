package corpusmatch

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleSnapshotJSON = `{"schema_version":1,"corpus_revision":7,"profiles":[
  {"profile_id":"p1","labels":{"manufacturer":"Google","model":"Chromecast","device_type":"media_player"},
   "variants":[{"variant_id":"v1","confidence_bp":9000,
     "shape":{"schema_version":1,"oui_prefixes":["acbc32"],"mdns_services":["_googlecast._tcp"]}}]}]}`

func TestManagedCorpus_LoadReloadAbsent(t *testing.T) {
	// Reset global state for a deterministic test.
	setActive(NewMatcher(nil))
	managedPath.Store(nil)

	dir := t.TempDir()

	// Absent corpus.json in an existing dir → no corpus, no error (OUI-only bundle).
	if err := EnableManagedCorpus(dir); err != nil {
		t.Fatalf("absent corpus should not error: %v", err)
	}
	if _, ok := Active().Match(ObservedSignals{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}}); ok {
		t.Error("no corpus should mean no match")
	}

	// Install a snapshot and reload → it now matches.
	if err := os.WriteFile(filepath.Join(dir, managedCorpusFile), []byte(sampleSnapshotJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ReloadCorpus(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	res, ok := Active().Match(ObservedSignals{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}})
	if !ok || res.Manufacturer != "Google" {
		t.Fatalf("expected a Google match after reload, got ok=%v %+v", ok, res)
	}

	// A later generation without corpus.json clears it back to empty.
	if err := os.Remove(filepath.Join(dir, managedCorpusFile)); err != nil {
		t.Fatal(err)
	}
	if err := ReloadCorpus(); err != nil {
		t.Fatalf("reload after removal: %v", err)
	}
	if _, ok := Active().Match(ObservedSignals{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}}); ok {
		t.Error("removed corpus should clear the active matcher")
	}
}

func TestManagedCorpus_BadSnapshotErrors(t *testing.T) {
	setActive(NewMatcher(nil))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, managedCorpusFile), []byte(`{"schema_version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnableManagedCorpus(dir); err == nil {
		t.Error("a present-but-unparseable snapshot must error (so OnInstalled can roll back)")
	}
}

func TestPrepareManagedCorpusDoesNotPublishBeforeActivate(t *testing.T) {
	setActive(NewMatcher(nil))
	managedPath.Store(nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, managedCorpusFile), []byte(sampleSnapshotJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareManagedCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	observed := ObservedSignals{OUIPrefixes: []string{"acbc32"}, MDNSServices: []string{"_googlecast._tcp"}}
	if _, ok := Active().Match(observed); ok {
		t.Fatal("prepare changed active matcher before Activate")
	}
	prepared.Activate()
	if result, ok := Active().Match(observed); !ok || result.Manufacturer != "Google" {
		t.Fatalf("Activate did not publish staged matcher: ok=%v result=%+v", ok, result)
	}

	if err := os.WriteFile(filepath.Join(dir, managedCorpusFile), []byte(`{"schema_version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReloadCorpus(); err == nil {
		t.Fatal("invalid replacement corpus prepared successfully")
	}
	if result, ok := Active().Match(observed); !ok || result.Manufacturer != "Google" {
		t.Fatalf("failed prepare changed last-good matcher: ok=%v result=%+v", ok, result)
	}
}

func TestPreparedCorpusGenerationTracksExactValidatedBytes(t *testing.T) {
	dir := t.TempDir()
	absent, err := PrepareManagedCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if absent.GenerationID() != "absent" {
		t.Fatalf("absent generation = %q", absent.GenerationID())
	}
	if err := os.WriteFile(filepath.Join(dir, managedCorpusFile), []byte(sampleSnapshotJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := PrepareManagedCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareManagedCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.GenerationID() == "" || first.GenerationID() == "absent" || first.GenerationID() != second.GenerationID() {
		t.Fatalf("validated generation IDs are not stable: first=%q second=%q", first.GenerationID(), second.GenerationID())
	}
	changed := []byte("\n" + sampleSnapshotJSON)
	if err := os.WriteFile(filepath.Join(dir, managedCorpusFile), changed, 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := PrepareManagedCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if third.GenerationID() == first.GenerationID() {
		t.Fatal("changed validated corpus bytes reused the prior generation ID")
	}
}
