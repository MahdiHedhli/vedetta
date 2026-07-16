package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

func TestCorpusDerivedSignals(t *testing.T) {
	dir := t.TempDir()
	snap := `{"schema_version":1,"corpus_revision":1,"profiles":[
	  {"profile_id":"p1","labels":{"manufacturer":"Google","model":"Chromecast","device_type":"media_player"},
	   "variants":[{"variant_id":"v1","confidence_bp":9000,
	     "shape":{"schema_version":1,"oui_prefixes":["acbc32"],"mdns_services":["_googlecast._tcp"]}}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "corpus.json"), []byte(snap), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corpusmatch.EnableManagedCorpus(dir); err != nil {
		t.Fatal(err)
	}
	// Reset the process-global matcher so it can't leak into other store tests.
	t.Cleanup(func() { _ = corpusmatch.EnableManagedCorpus(t.TempDir()) })

	// OUI + mDNS service = two families → a Chromecast class match.
	sigs := corpusDerivedSignals(discovery.DiscoveredHost{
		MACAddress: "ac:bc:32:11:22:33",
		Services:   []string{"_googlecast._tcp"},
	})
	got := map[string]string{}
	for _, s := range sigs {
		if s.source != SourceCorpus {
			t.Errorf("signal source = %q, want %q", s.source, SourceCorpus)
		}
		if s.confidence != 0.85 {
			t.Errorf("signal confidence = %v, want 0.85", s.confidence)
		}
		got[s.field] = s.value
	}
	if got["vendor"] != "Google" || got["model"] != "Chromecast" || got["device_type"] != "media_player" {
		t.Errorf("derived signals = %+v", got)
	}

	// A non-matching host yields nothing.
	if s := corpusDerivedSignals(discovery.DiscoveredHost{MACAddress: "00:00:00:00:00:00"}); s != nil {
		t.Errorf("a non-match should yield nil, got %+v", s)
	}
}
