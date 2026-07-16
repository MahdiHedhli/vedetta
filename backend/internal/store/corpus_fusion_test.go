package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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
	sigs := corpusDerivedSignalsForObserved(corpusObservedSignals(discovery.DiscoveredHost{
		MACAddress:      "ac:bc:32:11:22:33",
		Services:        []string{"_googlecast._tcp"},
		DiscoverySource: "passive_mdns",
	}))
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
	if s := corpusDerivedSignalsForObserved(corpusObservedSignals(discovery.DiscoveredHost{MACAddress: "00:00:00:00:00:00"})); s != nil {
		t.Errorf("a non-match should yield nil, got %+v", s)
	}
}

func TestCorpusObservedSignalsDoesNotRelabelActiveServicesAsMDNS(t *testing.T) {
	dir := t.TempDir()
	snap := `{"schema_version":1,"profiles":[{"profile_id":"p","labels":{"manufacturer":"Example","device_type":"media"},"variants":[{"variant_id":"v","confidence_bp":9000,"shape":{"schema_version":1,"oui_prefixes":["acbc32"],"mdns_services":["_googlecast._tcp"]}}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "corpus.json"), []byte(snap), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corpusmatch.EnableManagedCorpus(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = corpusmatch.EnableManagedCorpus(t.TempDir()) })

	active := corpusObservedSignals(discovery.DiscoveredHost{
		MACAddress: "ac:bc:32:11:22:33", Services: []string{"_googlecast._tcp"},
		DiscoverySource: "nmap_active",
	})
	if sigs := corpusDerivedSignalsForObserved(active); sigs != nil {
		t.Fatalf("active service names must not count as mDNS evidence: %+v", sigs)
	}
}

func TestCorpusFusionDoesNotRetainActiveServicesAsMDNS(t *testing.T) {
	dir := t.TempDir()
	snap := `{"schema_version":1,"profiles":[{"profile_id":"p","labels":{"manufacturer":"Example","device_type":"media"},"variants":[{"variant_id":"v","confidence_bp":9000,"shape":{"schema_version":1,"oui_prefixes":["acbc32"],"mdns_services":["_googlecast._tcp"]}}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "corpus.json"), []byte(snap), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corpusmatch.EnableManagedCorpus(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = corpusmatch.EnableManagedCorpus(t.TempDir()) })

	db := testDB(t)
	now := time.Now().UTC()
	for i, services := range [][]string{{"_googlecast._tcp"}, nil} {
		if _, err := db.UpsertDevice(discovery.DiscoveredHost{
			IPAddress: "192.0.2.52", MACAddress: "ac:bc:32:11:22:33",
			Services: services, DiscoverySource: "nmap_active", Status: "up",
		}, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	var corpusRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_signals WHERE source = ?`, SourceCorpus).Scan(&corpusRows); err != nil {
		t.Fatal(err)
	}
	if corpusRows != 0 {
		t.Fatalf("active service was retained as mDNS and produced %d corpus rows", corpusRows)
	}
}

func TestCorpusDerivedSignalsCapsConfidenceAtVariantConfidence(t *testing.T) {
	dir := t.TempDir()
	snap := `{"schema_version":1,"profiles":[{"profile_id":"p","labels":{"manufacturer":"Example","model":"Player","device_type":"media_player"},"variants":[{"variant_id":"v","confidence_bp":4200,"shape":{"schema_version":1,"ssdp_server_tokens":["example/player"]}}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "corpus.json"), []byte(snap), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corpusmatch.EnableManagedCorpus(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = corpusmatch.EnableManagedCorpus(t.TempDir()) })

	sigs := corpusDerivedSignalsForObserved(corpusObservedSignals(discovery.DiscoveredHost{
		DiscoverySource: "passive_ssdp",
		IdentityEvidence: []discovery.IdentityEvidence{{
			Type: "ssdp_server_token", Value: "Example/Player",
		}},
	}))
	if len(sigs) == 0 {
		t.Fatal("SSDP server token did not reach the corpus matcher")
	}
	for _, sig := range sigs {
		if sig.confidence != 0.42 {
			t.Fatalf("signal confidence = %v, want curator cap 0.42", sig.confidence)
		}
	}
}

func TestCorpusFusionCombinesCorrelatedReportsAndClearsStaleProjection(t *testing.T) {
	dir := t.TempDir()
	snap := `{"schema_version":1,"profiles":[{"profile_id":"p","labels":{"manufacturer":"Example Networks","model":"DIR-850L Wireless Router","device_type":"router"},"variants":[{"variant_id":"v","confidence_bp":9000,"shape":{"schema_version":1,"oui_prefixes":["00005e"],"mdns_services":["_router._tcp"]}}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "corpus.json"), []byte(snap), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corpusmatch.EnableManagedCorpus(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = corpusmatch.EnableManagedCorpus(t.TempDir()) })

	db := testDB(t)
	now := time.Now().UTC()
	if _, err := db.UpsertDevice(discovery.DiscoveredHost{
		IPAddress: "192.0.2.50", MACAddress: "00:00:5E:00:53:01",
		Status: "up", DiscoverySource: "nmap_active",
	}, now); err != nil {
		t.Fatal(err)
	}
	// The normal passive mDNS report has the source IP and service but no MAC. Core must
	// combine it with the already-correlated device MAC to reach two independent families.
	if _, err := db.UpsertDevice(discovery.DiscoveredHost{
		IPAddress: "192.0.2.50", Services: []string{"_router._tcp"},
		Status: "up", DiscoverySource: "passive_mdns",
	}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var model, deviceType string
	var eolRisk bool
	if err := db.QueryRow(`SELECT model, device_type, eol_risk FROM devices WHERE ip_address = ?`, "192.0.2.50").
		Scan(&model, &deviceType, &eolRisk); err != nil {
		t.Fatal(err)
	}
	if model != "DIR-850L Wireless Router" || deviceType != "router" {
		t.Fatalf("correlated corpus projection missing: model=%q type=%q", model, deviceType)
	}
	if eolRisk {
		t.Fatal("advisory corpus model fed the local EOL/risk engine")
	}

	// Removing the active corpus and observing the device again must remove the prior
	// projection instead of allowing it to sustain itself.
	if err := corpusmatch.EnableManagedCorpus(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertDevice(discovery.DiscoveredHost{
		IPAddress: "192.0.2.50", Services: []string{"_router._tcp"},
		Status: "up", DiscoverySource: "passive_mdns",
	}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	var corpusRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_signals WHERE source = ?`, SourceCorpus).Scan(&corpusRows); err != nil {
		t.Fatal(err)
	}
	if corpusRows != 0 {
		t.Fatalf("stale corpus rows remain after no-match observation: %d", corpusRows)
	}
	if err := db.QueryRow(`SELECT model, device_type FROM devices WHERE ip_address = ?`, "192.0.2.50").
		Scan(&model, &deviceType); err != nil {
		t.Fatal(err)
	}
	if model == "DIR-850L Wireless Router" || deviceType == "router" {
		t.Fatalf("stale corpus projection remains on device: model=%q type=%q", model, deviceType)
	}
}

func TestClearCorpusSignalsReprojectsQuietDevices(t *testing.T) {
	db := testDB(t)
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO devices
		(device_id, ip_address, mac_address, first_seen, last_seen, model, device_type, display_name)
		VALUES ('quiet-corpus-device', '192.0.2.51', '', ?, ?, 'Stale Model', 'camera', 'Stale Model')`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO device_signals
		(device_id, field, value, source, confidence, first_observed, last_observed)
		VALUES ('quiet-corpus-device', 'model', 'Stale Model', ?, 0.85, ?, ?),
		       ('quiet-corpus-device', 'device_type', 'camera', ?, 0.85, ?, ?)`,
		SourceCorpus, now, now, SourceCorpus, now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.ClearCorpusSignals(); err != nil {
		t.Fatal(err)
	}
	var model, deviceType, displayName string
	if err := db.QueryRow(`SELECT model, device_type, display_name FROM devices
		WHERE device_id = 'quiet-corpus-device'`).Scan(&model, &deviceType, &displayName); err != nil {
		t.Fatal(err)
	}
	if model != "" || deviceType != "" || displayName == "Stale Model" {
		t.Fatalf("quiet device was not reprojected: model=%q type=%q display=%q", model, deviceType, displayName)
	}
}
