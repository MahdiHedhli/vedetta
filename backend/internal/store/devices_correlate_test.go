package store

// Spec 004 correlation tests: identity resolver ordering, MAC-conflict veto,
// stoplist, confidence-weighted field merging, duplicate merge, multi-network
// attachments, label derivation, and an integration section (T5.1) covering the
// end-to-end scenarios from plan.md.
//
// All values are synthetic: RFC 5737 IPs (192.0.2.x) and 00:00:5E:00:53:xx MACs.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

// newCorrelationDB opens a fresh store (inline fallback schema, which is at
// post-019 parity) for correlation tests.
func newCorrelationDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "corr.db"))
	if err != nil {
		t.Fatalf("open corr db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type devRow struct {
	FirstSeen                                                time.Time
	MAC, Hostname, Vendor, Model, Segment, Display, Friendly string
}

func getDevice(t *testing.T, db *DB, ip string) *devRow {
	t.Helper()
	var out devRow
	err := db.QueryRow(`SELECT first_seen, COALESCE(mac_address,''), COALESCE(hostname,''),
		COALESCE(vendor,''), COALESCE(model,''), segment, COALESCE(display_name,''), COALESCE(friendly_name,'')
		FROM devices WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1`, ip).Scan(
		&out.FirstSeen, &out.MAC, &out.Hostname, &out.Vendor, &out.Model, &out.Segment, &out.Display, &out.Friendly)
	if err != nil {
		t.Fatalf("getDevice %s: %v", ip, err)
	}
	return &out
}

func countDevices(t *testing.T, db *DB) int {
	t.Helper()
	n, err := db.CountDevices()
	if err != nil {
		t.Fatalf("count devices: %v", err)
	}
	return n
}

// --- T3.1: stoplist -----------------------------------------------------------

func TestIsGenericHostname(t *testing.T) {
	generic := []string{"localhost", "android", "android-a1b2c3", "esp-1234", "esp32-ff00",
		"espressif", "printer", "camera", "unknown", "iPhone", "iPad.local", ""}
	for _, h := range generic {
		if !IsGenericHostname(h) {
			t.Errorf("IsGenericHostname(%q) = false, want true", h)
		}
	}
	specific := []string{"living-room-tv", "alices-macbook", "nvr-lobby", "chromecast-hall"}
	for _, h := range specific {
		if IsGenericHostname(h) {
			t.Errorf("IsGenericHostname(%q) = true, want false", h)
		}
	}
}

func TestConfidenceTableCoversDiscoverySources(t *testing.T) {
	// Every discovery_source value the sensor can send must map to a known signal
	// source with a non-zero confidence.
	sources := []string{"passive_arp", "arp_cache", "passive_dhcp", "passive_mdns", "passive_ssdp",
		"nmap_active", "native_icmp", nativeICMPBoundSource, arpLiveFusionSource}
	for _, ds := range sources {
		sig := discoverySourceToSignal(ds)
		if ConfidenceForSource(sig) <= 0 {
			t.Errorf("discovery_source %q -> signal %q has non-positive confidence", ds, sig)
		}
	}
}

// --- T3.2: DHCP churn (same MAC, new IP → one device) ------------------------

func TestUpsert_DHCPChurn_SameMACNewIP(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	mac := "00:00:5E:00:53:0A"

	for i, ip := range []string{"192.0.2.20", "192.0.2.21", "192.0.2.22"} {
		host := discovery.DiscoveredHost{IPAddress: ip, MACAddress: mac, Hostname: "workstation-1", DiscoverySource: "passive_arp"}
		isNew, err := db.UpsertDevice(host, now.Add(time.Duration(i)*time.Minute), "lan")
		if err != nil {
			t.Fatalf("upsert %s: %v", ip, err)
		}
		if i == 0 && !isNew {
			t.Fatal("first observation should be new")
		}
		if i > 0 && isNew {
			t.Fatalf("observation %d (%s) unexpectedly created a new device", i, ip)
		}
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("DHCP churn produced %d devices, want 1", n)
	}
	// Canonical row tracks the most-recent IP.
	dev := getDevice(t, db, "192.0.2.22")
	if dev.MAC != mac {
		t.Errorf("device MAC = %q, want %q", dev.MAC, mac)
	}
}

// --- T3.2: MAC-conflict veto (same IP reused by a different MAC) --------------

func TestUpsert_MACConflictVeto_CreatesSecondDevice(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()

	h1 := discovery.DiscoveredHost{IPAddress: "192.0.2.30", MACAddress: "00:00:5E:00:53:01", DiscoverySource: "passive_arp"}
	if _, err := db.UpsertDevice(h1, now, "lan"); err != nil {
		t.Fatalf("upsert h1: %v", err)
	}
	// Same IP, DIFFERENT MAC → must NOT steal the record; a new device is created.
	h2 := discovery.DiscoveredHost{IPAddress: "192.0.2.30", MACAddress: "00:00:5E:00:53:02", DiscoverySource: "passive_arp"}
	isNew, err := db.UpsertDevice(h2, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert h2: %v", err)
	}
	if !isNew {
		t.Fatal("MAC-conflict on shared IP must create a new device")
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("MAC-conflict veto produced %d devices, want 2", n)
	}
}

// --- T3.3: MAC-less mDNS then ARP+MAC link-up (merge, not duplicate) ----------

func TestUpsert_MaclessThenMAC_LinksUp(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()

	// 1) MAC-less mDNS observation carrying a rich model + friendly name.
	mdns := discovery.DiscoveredHost{
		IPAddress:       "192.0.2.40",
		Hostname:        "chromecast-hall",
		Model:           "Chromecast Ultra",
		FriendlyName:    "Living Room TV",
		Services:        []string{"_googlecast._tcp"},
		DiscoverySource: "passive_mdns",
	}
	if _, err := db.UpsertDevice(mdns, now, "lan"); err != nil {
		t.Fatalf("upsert mdns: %v", err)
	}
	// 2) ARP observation for the same IP now carrying a MAC (and OUI vendor).
	arp := discovery.DiscoveredHost{
		IPAddress:       "192.0.2.40",
		MACAddress:      "00:00:5E:00:53:0B",
		Vendor:          "Google",
		DiscoverySource: "passive_arp",
	}
	if _, err := db.UpsertDevice(arp, now.Add(time.Minute), "lan"); err != nil {
		t.Fatalf("upsert arp: %v", err)
	}

	if n := countDevices(t, db); n != 1 {
		t.Fatalf("MAC-less→MAC link-up produced %d devices, want 1", n)
	}
	dev := getDevice(t, db, "192.0.2.40")
	if dev.MAC != "00:00:5E:00:53:0B" {
		t.Errorf("linked device MAC = %q, want the ARP MAC", dev.MAC)
	}
	if dev.Model != "Chromecast Ultra" {
		t.Errorf("linked device lost mDNS model: got %q", dev.Model)
	}
	if dev.Friendly != "Living Room TV" {
		t.Errorf("linked device lost friendly name: got %q", dev.Friendly)
	}
	if dev.Display != "Living Room TV" {
		t.Errorf("display_name = %q, want friendly name to win", dev.Display)
	}
}

// TestUpsert_MergeMaclessDuplicate exercises the T3.3 path where a MAC-bearing
// record A and a distinct MAC-less record B both pre-exist and a later report
// with the MAC + B's hostname folds B into A.
func TestUpsert_MergeMaclessDuplicate(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Now().UTC().Add(-2 * time.Hour)
	mac := "00:00:5E:00:53:0C"

	// A: MAC-bearing, seen earliest.
	a := discovery.DiscoveredHost{IPAddress: "192.0.2.50", MACAddress: mac, DiscoverySource: "passive_arp"}
	if _, err := db.UpsertDevice(a, base, "lan"); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	// B: MAC-less mDNS duplicate on a DIFFERENT IP, same segment, distinct hostname.
	b := discovery.DiscoveredHost{IPAddress: "192.0.2.51", Hostname: "media-box", Model: "Shield TV", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(b, base.Add(time.Minute), "lan"); err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("setup expected 2 devices, got %d", n)
	}

	// Report carrying the MAC (A) AND B's hostname → merge B into A.
	link := discovery.DiscoveredHost{IPAddress: "192.0.2.52", MACAddress: mac, Hostname: "media-box", DiscoverySource: "passive_arp"}
	if _, err := db.UpsertDevice(link, time.Now().UTC(), "lan"); err != nil {
		t.Fatalf("upsert link: %v", err)
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("after merge want 1 device, got %d", n)
	}
	// Survivor keeps MIN(first_seen) == A's first_seen and B's model.
	var first time.Time
	var model string
	if err := db.QueryRow(`SELECT first_seen, COALESCE(model,'') FROM devices WHERE mac_address = ?`, mac).Scan(&first, &model); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if first.After(base.Add(30 * time.Second)) {
		t.Errorf("survivor first_seen = %v, want ~A's earliest (%v)", first, base)
	}
	if model != "Shield TV" {
		t.Errorf("survivor model = %q, want B's model folded in", model)
	}
}

// --- T3.4: confidence-weighted field merging ---------------------------------

func TestUpsert_ConfidenceMerge_OUIDoesNotOverwriteMDNS(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	mac := "00:00:5E:00:53:0D"

	// High-confidence mDNS TXT model first.
	mdns := discovery.DiscoveredHost{IPAddress: "192.0.2.60", MACAddress: mac, Model: "Chromecast Ultra", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(mdns, now, "lan"); err != nil {
		t.Fatalf("upsert mdns: %v", err)
	}
	// Later ARP/nmap observation with only a weak vendor and NO model — must not
	// wipe the model.
	arp := discovery.DiscoveredHost{IPAddress: "192.0.2.60", MACAddress: mac, Vendor: "Generic", DiscoverySource: "nmap_active"}
	if _, err := db.UpsertDevice(arp, now.Add(time.Minute), "lan"); err != nil {
		t.Fatalf("upsert arp: %v", err)
	}
	dev := getDevice(t, db, "192.0.2.60")
	if dev.Model != "Chromecast Ultra" {
		t.Errorf("model = %q, want mDNS model preserved against weaker source", dev.Model)
	}
}

func TestUpdateDeviceFingerprint_UserCorrectionLocks(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	mac := "00:00:5E:00:53:0E"

	host := discovery.DiscoveredHost{IPAddress: "192.0.2.70", MACAddress: mac, Model: "Chromecast Ultra", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(host, now, "lan"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var deviceID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address = ?`, mac).Scan(&deviceID); err != nil {
		t.Fatalf("read device id: %v", err)
	}
	// User corrects the model.
	if err := db.UpdateDeviceFingerprint(deviceID, "", "", "", "Corrected Model X"); err != nil {
		t.Fatalf("correction: %v", err)
	}
	// A later mDNS report with a different model must NOT overwrite the locked field.
	host2 := discovery.DiscoveredHost{IPAddress: "192.0.2.70", MACAddress: mac, Model: "Some Other Model", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(host2, now.Add(time.Minute), "lan"); err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	dev := getDevice(t, db, "192.0.2.70")
	if dev.Model != "Corrected Model X" {
		t.Errorf("model = %q, want user-corrected value to stay locked", dev.Model)
	}
}

// --- T3.5: multi-network attachments -----------------------------------------

func TestUpsert_MultiSegmentRoam(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	mac := "00:00:5E:00:53:0F"

	lan := discovery.DiscoveredHost{IPAddress: "192.0.2.80", MACAddress: mac, DiscoverySource: "passive_arp"}
	if _, err := db.UpsertDevice(lan, now, "lan"); err != nil {
		t.Fatalf("upsert lan: %v", err)
	}
	iot := discovery.DiscoveredHost{IPAddress: "198.51.100.80", MACAddress: mac, DiscoverySource: "passive_arp"}
	if _, err := db.UpsertDevice(iot, now.Add(time.Minute), "iot"); err != nil {
		t.Fatalf("upsert iot: %v", err)
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("roam produced %d devices, want 1", n)
	}
	var deviceID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address = ?`, mac).Scan(&deviceID); err != nil {
		t.Fatalf("read id: %v", err)
	}
	segs, err := db.GetDeviceSegments(deviceID)
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(segs) != 2 {
		t.Fatalf("attachments = %v, want two segments", segs)
	}
	// Most-recent attachment (iot) is the canonical segment.
	var seg, ip string
	if err := db.QueryRow(`SELECT segment, ip_address FROM devices WHERE device_id = ?`, deviceID).Scan(&seg, &ip); err != nil {
		t.Fatalf("read canonical: %v", err)
	}
	if seg != "iot" || ip != "198.51.100.80" {
		t.Errorf("canonical (segment,ip) = (%q,%q), want (iot,198.51.100.80)", seg, ip)
	}
}

// --- SNR: two devices with identical generic hostname must NOT merge ---------

func TestUpsert_IdenticalGenericHostname_NotMerged(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()

	d1 := discovery.DiscoveredHost{IPAddress: "192.0.2.90", MACAddress: "00:00:5E:00:53:11", Hostname: "espressif", DiscoverySource: "passive_dhcp"}
	if _, err := db.UpsertDevice(d1, now, "iot"); err != nil {
		t.Fatalf("upsert d1: %v", err)
	}
	d2 := discovery.DiscoveredHost{IPAddress: "192.0.2.91", MACAddress: "00:00:5E:00:53:12", Hostname: "espressif", DiscoverySource: "passive_dhcp"}
	isNew, err := db.UpsertDevice(d2, now.Add(time.Minute), "iot")
	if err != nil {
		t.Fatalf("upsert d2: %v", err)
	}
	if !isNew {
		t.Fatal("second generic-hostname device should be new, not merged")
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("generic-hostname devices merged: got %d, want 2", n)
	}
}

// --- T4.2: label deriver precedence ------------------------------------------

func TestDeriveDisplayName_Precedence(t *testing.T) {
	cases := []struct {
		name                                           string
		custom, friendly, model, vendor, host, mac, ip string
		want                                           string
	}{
		{"custom wins", "My TV", "Living Room TV", "Chromecast Ultra", "Google", "chromecast-hall", "00:00:5E:00:53:0A", "192.0.2.10", "My TV"},
		{"friendly next", "", "Living Room TV", "Chromecast Ultra", "Google", "chromecast-hall", "00:00:5E:00:53:0A", "192.0.2.10", "Living Room TV"},
		{"model+vendor", "", "", "Chromecast Ultra", "Google", "chromecast-hall", "00:00:5E:00:53:0A", "192.0.2.10", "Chromecast Ultra (Google)"},
		{"cleaned hostname", "", "", "", "", "living-room-tv.local", "00:00:5E:00:53:0A", "192.0.2.10", "living-room-tv"},
		{"generic hostname skipped -> vendor+mac", "", "", "", "Espressif", "espressif", "00:00:5E:00:53:2A", "192.0.2.10", "Espressif 53:2A"},
		{"ip last resort", "", "", "", "", "localhost", "", "192.0.2.10", "192.0.2.10"},
	}
	for _, c := range cases {
		got := deriveDisplayName(c.custom, c.friendly, c.model, c.vendor, c.host, c.mac, c.ip)
		if got != c.want {
			t.Errorf("%s: deriveDisplayName = %q, want %q", c.name, got, c.want)
		}
	}
}

// --- T4.1: old sensor payload (no friendly_name) still works ------------------

func TestUpsert_OldPayloadNoFriendlyName(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	host := discovery.DiscoveredHost{IPAddress: "192.0.2.100", MACAddress: "00:00:5E:00:53:13", Hostname: "old-sensor-host", DiscoverySource: "passive_arp"}
	if _, err := db.UpsertDevice(host, now, "lan"); err != nil {
		t.Fatalf("old payload upsert: %v", err)
	}
	dev := getDevice(t, db, "192.0.2.100")
	if dev.Friendly != "" {
		t.Errorf("friendly_name = %q, want empty for old payload", dev.Friendly)
	}
	if dev.Display == "" {
		t.Error("display_name should still be derived without a friendly name")
	}
}

// --- Wrong-merge regression: ambiguous mDNS friendly name --------------------

// TestUpsert_AmbiguousMDNSName_NotMerged guards the mDNS-name identity rule
// (matchByAlias rule 2). mDNS instance / friendly names are NOT unique — two
// units advertising "Office Printer" on the same segment is routine. Without the
// uniqueness guard, the second device's report matched the first's mdns_name
// alias and was silently folded in, collapsing two physically distinct devices
// into one (a wrong merge; spec NFR-4 prefers a duplicate row over a wrong merge).
func TestUpsert_AmbiguousMDNSName_NotMerged(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()

	// Two distinct MAC-less devices sharing the friendly mDNS name "Office Printer".
	d1 := discovery.DiscoveredHost{IPAddress: "192.0.2.180", Hostname: "printer-a", FriendlyName: "Office Printer", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(d1, now, "lan"); err != nil {
		t.Fatalf("upsert d1: %v", err)
	}
	d2 := discovery.DiscoveredHost{IPAddress: "192.0.2.181", Hostname: "printer-b", FriendlyName: "Office Printer", DiscoverySource: "passive_mdns"}
	isNew, err := db.UpsertDevice(d2, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert d2: %v", err)
	}
	if !isNew {
		t.Fatal("second device with an ambiguous shared mDNS name must be new, not merged")
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("ambiguous mDNS name collapsed distinct devices: got %d, want 2", n)
	}

	// A third report reusing the ambiguous name must also stay ambiguous (no match).
	d3 := discovery.DiscoveredHost{IPAddress: "192.0.2.182", Hostname: "printer-c", FriendlyName: "Office Printer", DiscoverySource: "passive_mdns"}
	isNew, err = db.UpsertDevice(d3, now.Add(2*time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert d3: %v", err)
	}
	if !isNew {
		t.Fatal("third ambiguous-name device must be new, not merged into an arbitrary earlier one")
	}
	if n := countDevices(t, db); n != 3 {
		t.Fatalf("ambiguous mDNS name still merging: got %d, want 3", n)
	}
}

// TestUpsert_UniqueMDNSName_StillLinks confirms the guard does not over-block:
// a UNIQUE mDNS friendly name still links a later MAC-less report to the same
// device (name continuity across IP churn), i.e. we didn't disable rule 2.
func TestUpsert_UniqueMDNSName_StillLinks(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()

	first := discovery.DiscoveredHost{IPAddress: "192.0.2.185", Hostname: "cast-hall", FriendlyName: "Basement Cast", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(first, now, "lan"); err != nil {
		t.Fatalf("upsert first: %v", err)
	}
	// Same friendly name, new IP, still MAC-less → should link (unique name).
	second := discovery.DiscoveredHost{IPAddress: "192.0.2.186", Hostname: "cast-hall", FriendlyName: "Basement Cast", DiscoverySource: "passive_mdns"}
	isNew, err := db.UpsertDevice(second, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert second: %v", err)
	}
	if isNew {
		t.Fatal("unique mDNS name should link the later report, not create a duplicate")
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("unique mDNS name failed to link: got %d devices, want 1", n)
	}
}

// --- Wrong-merge regression: MAC-conflict veto on the ALIAS rules ------------

// TestUpsert_DirectHostnameRule_MACConflictVeto is the load-bearing regression
// for a confirmed critical data-integrity bug: an observation carrying a
// BRAND-NEW MAC X (no rule-1 MAC match) that shares a specific hostname with a
// stored record whose MAC is a DIFFERENT non-empty Y was silently folded onto
// that record via the direct hostname rule (matchByAlias rule 3), and the
// mac_address CASE-write in UpsertDevice then overwrote Y with X — collapsing two
// physically distinct devices into one and flipping the survivor's MAC. Spec FR-4
// ("MUST NOT re-assign a record whose stored MAC differs") / NFR-4 ("prefer a
// duplicate row over a wrong merge") forbid this. The fix adds a MAC-conflict veto
// (macConflicts) to the mDNS-name and hostname alias rules.
//
// Load-bearing: with the veto removed this asserts 2 devices but gets 1.
func TestUpsert_DirectHostnameRule_MACConflictVeto(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	macY := "00:00:5E:00:53:D2"
	macX := "00:00:5E:00:53:D1"

	// Stored device B: MAC Y, specific hostname (e.g. a DHCP-provided name).
	b := discovery.DiscoveredHost{IPAddress: "192.0.2.31", MACAddress: macY, Hostname: "nvr-lobby", DiscoverySource: "passive_dhcp"}
	if _, err := db.UpsertDevice(b, now, "lan"); err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	// Replacement/other hardware: brand-new MAC X, same specific hostname, new IP.
	in := discovery.DiscoveredHost{IPAddress: "192.0.2.32", MACAddress: macX, Hostname: "nvr-lobby", DiscoverySource: "passive_dhcp"}
	isNew, err := db.UpsertDevice(in, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert in: %v", err)
	}
	if !isNew {
		t.Fatal("new MAC sharing a hostname with a differently-MAC'd record must create a new device")
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("WRONG MERGE via direct hostname rule across a MAC conflict: got %d devices, want 2", n)
	}
	// The original MAC-Y record must be intact (not overwritten to X).
	var cntY int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, macY).Scan(&cntY); err != nil {
		t.Fatalf("count macY: %v", err)
	}
	if cntY != 1 {
		t.Fatalf("stored MAC-Y record was overwritten/destroyed: count=%d, want 1", cntY)
	}
}

// TestUpsert_DirectMDNSRule_MACConflictVeto is the same regression via the direct
// mDNS-name rule (matchByAlias rule 2): a brand-new MAC X sharing a UNIQUE mDNS
// friendly name with a differently-MAC'd stored device must NOT steal that record.
// Two Chromecasts/cameras that happen to share a friendly name are distinct
// devices when their MACs differ.
//
// Load-bearing: with the veto removed this asserts 2 devices but gets 1.
func TestUpsert_DirectMDNSRule_MACConflictVeto(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	macY := "00:00:5E:00:53:E2"
	macX := "00:00:5E:00:53:E1"

	b := discovery.DiscoveredHost{IPAddress: "192.0.2.41", MACAddress: macY, FriendlyName: "Garage Cam", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(b, now, "lan"); err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	in := discovery.DiscoveredHost{IPAddress: "192.0.2.42", MACAddress: macX, FriendlyName: "Garage Cam", DiscoverySource: "passive_mdns"}
	isNew, err := db.UpsertDevice(in, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert in: %v", err)
	}
	if !isNew {
		t.Fatal("new MAC sharing an mDNS name with a differently-MAC'd record must create a new device")
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("WRONG MERGE via direct mDNS rule across a MAC conflict: got %d devices, want 2", n)
	}
	var cntY int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, macY).Scan(&cntY); err != nil {
		t.Fatalf("count macY: %v", err)
	}
	if cntY != 1 {
		t.Fatalf("stored MAC-Y record was overwritten/destroyed: count=%d, want 1", cntY)
	}
}

// TestUpsert_MAClessLinkUp_SurvivesVeto proves the new MAC-conflict veto does NOT
// over-block the legitimate MAC-less continuity path: a MAC-less device known by
// hostname/mDNS name must still link up when ARP later supplies a MAC (candidate
// has no stored MAC, so there is no conflict). This is the inverse guard that
// keeps the veto from regressing the core "survive DHCP churn" behavior.
func TestUpsert_MAClessLinkUp_SurvivesVeto(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()

	// MAC-less mDNS device with a specific hostname.
	mdns := discovery.DiscoveredHost{IPAddress: "192.0.2.45", Hostname: "cast-den", FriendlyName: "Den Cast", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(mdns, now, "lan"); err != nil {
		t.Fatalf("upsert mdns: %v", err)
	}
	// Later report supplies a MAC while sharing the hostname → must link (no conflict).
	arp := discovery.DiscoveredHost{IPAddress: "192.0.2.46", MACAddress: "00:00:5E:00:53:E9", Hostname: "cast-den", DiscoverySource: "passive_dhcp"}
	isNew, err := db.UpsertDevice(arp, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert arp: %v", err)
	}
	if isNew {
		t.Fatal("MAC-less→MAC link-up must NOT be blocked by the MAC-conflict veto")
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("veto over-blocked legitimate link-up: got %d devices, want 1", n)
	}
}

// TestUpsert_RandomizedMACRotation_MDNSNameFolds proves the sprawl fix: a device
// that keeps a UNIQUE mDNS friendly name but rotates its RANDOMIZED (locally
// administered) MAC must fold into the existing record instead of spawning a new
// device row per rotation. This is the dominant modern case — phones/laptops with
// private Wi-Fi addresses on by default.
func TestUpsert_RandomizedMACRotation_MDNSNameFolds(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	// Locally administered (U/L bit set: first octet 0x02) synthetic MACs.
	rand1 := "02:00:5E:00:53:01"
	rand2 := "02:00:5E:00:53:02"
	rand3 := "02:00:5E:00:53:03"

	first := discovery.DiscoveredHost{IPAddress: "192.0.2.51", MACAddress: rand1, FriendlyName: "Alex Phone", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(first, now, "lan"); err != nil {
		t.Fatalf("upsert first: %v", err)
	}
	// A week later the private address has rotated. Same unique mDNS name.
	rot := discovery.DiscoveredHost{IPAddress: "192.0.2.52", MACAddress: rand2, FriendlyName: "Alex Phone", DiscoverySource: "passive_mdns"}
	isNew, err := db.UpsertDevice(rot, now.Add(6*24*time.Hour), "lan")
	if err != nil {
		t.Fatalf("upsert rotation: %v", err)
	}
	if isNew {
		t.Fatal("a rotated randomized MAC under a unique mDNS name must fold, not create a new device")
	}
	// A second rotation still folds (the record now carries rand2, itself randomized).
	rot2 := discovery.DiscoveredHost{IPAddress: "192.0.2.53", MACAddress: rand3, FriendlyName: "Alex Phone", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(rot2, now.Add(12*24*time.Hour), "lan"); err != nil {
		t.Fatalf("upsert rotation 2: %v", err)
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("randomized-MAC rotation sprawled: got %d devices, want 1", n)
	}
}

// TestUpsert_RandomizedMACRotation_HostnameFolds is the same fix via the direct
// hostname rule: a specific (non-generic) hostname carries the continuity while
// the randomized MAC rotates.
func TestUpsert_RandomizedMACRotation_HostnameFolds(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	rand1 := "06:00:5E:00:53:11"
	rand2 := "06:00:5E:00:53:12"

	first := discovery.DiscoveredHost{IPAddress: "192.0.2.61", MACAddress: rand1, Hostname: "alex-laptop", DiscoverySource: "passive_dhcp"}
	if _, err := db.UpsertDevice(first, now, "lan"); err != nil {
		t.Fatalf("upsert first: %v", err)
	}
	rot := discovery.DiscoveredHost{IPAddress: "192.0.2.62", MACAddress: rand2, Hostname: "alex-laptop", DiscoverySource: "passive_dhcp"}
	isNew, err := db.UpsertDevice(rot, now.Add(time.Hour), "lan")
	if err != nil {
		t.Fatalf("upsert rotation: %v", err)
	}
	if isNew {
		t.Fatal("a rotated randomized MAC under a unique specific hostname must fold, not create a new device")
	}
	if n := countDevices(t, db); n != 1 {
		t.Fatalf("randomized-MAC rotation sprawled: got %d devices, want 1", n)
	}
}

// TestUpsert_RandomizedMAC_DoesNotClobberStableHardware proves the relaxation is
// bounded: a randomized observation that shares an alias with a candidate pinned
// to a STABLE (globally administered) MAC must NOT fold — folding would risk a
// wrong merge and overwrite a durable hardware key with an ephemeral one. Prefer a
// duplicate row (spec NFR-4).
func TestUpsert_RandomizedMAC_DoesNotClobberStableHardware(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	stable := "00:00:5E:00:53:F1" // globally administered (U/L bit clear)
	random := "02:00:5E:00:53:F2" // locally administered

	burnedIn := discovery.DiscoveredHost{IPAddress: "192.0.2.71", MACAddress: stable, FriendlyName: "Living Room TV", DiscoverySource: "passive_mdns"}
	if _, err := db.UpsertDevice(burnedIn, now, "lan"); err != nil {
		t.Fatalf("upsert burned-in: %v", err)
	}
	in := discovery.DiscoveredHost{IPAddress: "192.0.2.72", MACAddress: random, FriendlyName: "Living Room TV", DiscoverySource: "passive_mdns"}
	isNew, err := db.UpsertDevice(in, now.Add(time.Minute), "lan")
	if err != nil {
		t.Fatalf("upsert randomized: %v", err)
	}
	if !isNew {
		t.Fatal("a randomized observation must not fold into a stable-MAC record on an alias alone")
	}
	if n := countDevices(t, db); n != 2 {
		t.Fatalf("randomized observation clobbered stable hardware: got %d devices, want 2", n)
	}
	// The stable MAC must survive intact.
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, stable).Scan(&cnt); err != nil {
		t.Fatalf("count stable: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("stable MAC record was overwritten: count=%d, want 1", cnt)
	}
}

// TestRandomizedMACAliasVetoChecksMergedFamily protects the soft-merge audit
// model. A stable hardware MAC can remain on a redirected child when an operator
// chooses a MAC-less or randomized record as the canonical target. The alias
// relaxation must inspect that whole family; checking only the canonical row
// would allow a new randomized observation to fold into a family already pinned
// to stable hardware.
func TestRandomizedMACAliasVetoChecksMergedFamily(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	random := "02:00:5E:00:53:E1"
	stable := "00:00:5E:00:53:E2"

	if _, err := db.UpsertDevice(discovery.DiscoveredHost{
		IPAddress: "192.0.2.81", MACAddress: random, Hostname: "alex-laptop",
		DiscoverySource: "passive_dhcp",
	}, now, "lan"); err != nil {
		t.Fatalf("upsert randomized canonical candidate: %v", err)
	}
	if _, err := db.UpsertDevice(discovery.DiscoveredHost{
		IPAddress: "192.0.2.82", MACAddress: stable, Hostname: "stable-child",
		DiscoverySource: "passive_dhcp",
	}, now.Add(time.Second), "lan"); err != nil {
		t.Fatalf("upsert stable child: %v", err)
	}

	var canonicalID, stableID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address = ?`, random).Scan(&canonicalID); err != nil {
		t.Fatalf("read randomized candidate: %v", err)
	}
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address = ?`, stable).Scan(&stableID); err != nil {
		t.Fatalf("read stable child: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.mergeDevices(tx, canonicalID, stableID, "operator merge fixture"); err != nil {
		t.Fatalf("merge stable child under randomized canonical: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit merge fixture: %v", err)
	}

	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	conflict, err := db.macConflictsForAlias(tx, canonicalID, "06:00:5E:00:53:E3")
	if err != nil {
		t.Fatalf("check randomized alias conflict: %v", err)
	}
	if !conflict {
		t.Fatal("stable MAC retained on a merged child did not veto randomized alias folding")
	}
}

// seedMACOwner inserts a bare device row and gives it active MAC identity
// evidence for `mac`, so a test can construct the corrupt >1-owner-of-one-MAC
// state that the runaway-sprawl loop produced in production.
func seedMACOwner(t *testing.T, db *DB, deviceID string, firstSeen time.Time, mac, segment, sensorID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO devices (device_id, first_seen, last_seen, ip_address, mac_address, segment)
		VALUES (?, ?, ?, ?, ?, ?)`, deviceID, firstSeen, firstSeen, "", mac, segment); err != nil {
		t.Fatalf("seed device %s: %v", deviceID, err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := db.upsertIdentityEvidenceTx(tx, deviceID, segment, sensorID,
		DeviceIdentityEvidenceInput{Type: "mac", Value: mac, Source: "event", Confidence: 0.95, Sensitive: true},
		firstSeen, false); err != nil {
		tx.Rollback()
		t.Fatalf("seed mac evidence for %s: %v", deviceID, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed %s: %v", deviceID, err)
	}
}

// TestResolve_RunawayMACConflict_AttachesToDeterministicOwner is the regression
// guard for the runaway device-sprawl loop: a burned-in MAC bound to MULTIPLE
// canonical devices (data corruption) must resolve to ONE deterministic owner
// (oldest first_seen), NOT return an empty conflict. Before the fix, the empty
// conflict made UpsertDevice mint a brand-new device on every observation, adding
// another owner and growing the conflict without bound.
func TestResolve_RunawayMACConflict_AttachesToDeterministicOwner(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	mac := "00:00:5E:00:53:01" // globally administered (burned-in)

	// Seed a corrupt 3-owner state, oldest first.
	seedMACOwner(t, db, "dev-oldest", base, mac, "lan", "sensor-a")
	seedMACOwner(t, db, "dev-mid", base.Add(time.Hour), mac, "lan", "sensor-a")
	seedMACOwner(t, db, "dev-new", base.Add(2*time.Hour), mac, "lan", "sensor-a")
	if n := countDevices(t, db); n != 3 {
		t.Fatalf("seed expected 3 devices, got %d", n)
	}

	got := resolveStrengthMAC(t, db, base.Add(3*time.Hour), "sensor-a", "lan", mac)
	if got.DeviceID != "dev-oldest" {
		t.Fatalf("multi-owner MAC must resolve to the oldest owner deterministically, got %+v", got)
	}
	if got.Reason != "mac_identity_evidence" {
		t.Fatalf("expected mac_identity_evidence, got reason %q", got.Reason)
	}

	// The loop is broken: repeated observations attach to the survivor and create
	// NO new devices.
	for i := 0; i < 5; i++ {
		if _, err := db.UpsertDevice(discovery.DiscoveredHost{
			IPAddress: "192.0.2.80", MACAddress: mac, DiscoverySource: "passive_arp",
		}, base.Add(time.Duration(4+i)*time.Hour), "lan"); err != nil {
			t.Fatalf("observation %d: %v", i, err)
		}
	}
	if n := countDevices(t, db); n != 3 {
		t.Fatalf("runaway loop not broken: got %d devices after 5 observations, want 3", n)
	}
}

// TestResolve_RunawayMAC_TwoFormats_StillCollapses guards the normalization fix:
// the same burned-in MAC presented in two textual formats within one request (the
// request MAC is appended as one mac evidence item, plus an explicit mac evidence
// item in another format) must still be treated as ONE value and collapse to the
// deterministic owner — not read as two distinct values and fall through to a veto.
func TestResolve_RunawayMAC_TwoFormats_StillCollapses(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	mac := "00:00:5E:00:53:01"

	seedMACOwner(t, db, "surv", base, mac, "lan", "sensor-a")
	seedMACOwner(t, db, "dup1", base.Add(time.Hour), mac, "lan", "sensor-a")

	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(2 * time.Hour), Segment: "lan", SensorID: "sensor-a",
		MACAddress: "00:00:5E:00:53:01", // colon form, appended as mac evidence
		Evidence:   []DeviceIdentityEvidenceInput{{Type: "mac", Value: "00-00-5e-00-53-01"}}, // hyphen/lower form of the same MAC
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.DeviceID != "surv" || got.Reason != "mac_identity_evidence" {
		t.Fatalf("same MAC in two formats must still collapse to the survivor, got %+v", got)
	}
}

// TestResolve_RandomizedMultiOwner_StillConflicts proves the collapse is scoped to
// burned-in MACs: a randomized (locally administered) MAC held by two devices in a
// segment stays a conflict (macOwnerConsolidable=false), so #114's randomized-MAC
// handling and the general conflict veto are unaffected.
func TestResolve_RandomizedMultiOwner_StillConflicts(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	mac := "02:00:5E:00:53:01" // locally administered (randomized)

	seedMACOwner(t, db, "rand-a", base, mac, "lan", "sensor-a")
	seedMACOwner(t, db, "rand-b", base.Add(time.Hour), mac, "lan", "sensor-a")

	got := resolveStrengthMAC(t, db, base.Add(2*time.Hour), "sensor-a", "lan", mac)
	if got.DeviceID != "" || got.Reason != "conflicting_identity_evidence" {
		t.Fatalf("randomized multi-owner MAC must stay a conflict, got %+v", got)
	}
}

// TestResolve_TwoDistinctBurnedInMACs_StillConflicts proves a genuine different-MAC
// conflict (two distinct burned-in values matched) is NOT collapsed.
func TestResolve_TwoDistinctBurnedInMACs_StillConflicts(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 5, 27, 21, 14, 14, 0, time.UTC)
	macA := "00:00:5E:00:53:0A"
	macB := "00:00:5E:00:53:0B"
	seedMACOwner(t, db, "dev-a", base, macA, "lan", "sensor-a")
	seedMACOwner(t, db, "dev-b", base.Add(time.Hour), macB, "lan", "sensor-a")

	// An observation presenting BOTH MACs matches two different owners by two
	// distinct values -> genuine conflict, no collapse.
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(2 * time.Hour), Segment: "lan", SensorID: "sensor-a",
		Evidence: []DeviceIdentityEvidenceInput{
			{Type: "mac", Value: macA}, {Type: "mac", Value: macB},
		},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.DeviceID != "" || got.Reason != "conflicting_identity_evidence" {
		t.Fatalf("two distinct burned-in MACs must stay a conflict, got %+v", got)
	}
}

// --- Data-integrity regression: deterministic canonical resolution -----------

// TestResolveCanonicalFields_DeterministicTie guards resolveCanonicalFields
// against nondeterministic tie-breaking. Two equal-confidence signals for the
// same field must always resolve to the SAME winner across upserts; without the
// ORDER BY the winner depended on SQLite row order and the canonical value could
// flip with no new evidence.
func TestResolveCanonicalFields_DeterministicTie(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Now().UTC()
	deviceID := "dev-tie-test"

	if _, err := db.Exec(`INSERT INTO devices (device_id, first_seen, last_seen, ip_address, mac_address, segment)
		VALUES (?, ?, ?, '192.0.2.200', '', 'lan')`, deviceID, now, now); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Two DIFFERENT sources at the SAME confidence for the same field, with a
	// clear recency order (sourceB observed later → deterministic winner).
	writeSignal := func(source, value string, conf float64, observed time.Time) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO device_signals
			(device_id, field, value, source, confidence, first_observed, last_observed)
			VALUES (?, 'vendor', ?, ?, ?, ?, ?)`, deviceID, value, source, conf, observed, observed); err != nil {
			t.Fatalf("write signal %s: %v", source, err)
		}
	}
	writeSignal("mdns_txt", "VendorOlder", 0.9, now.Add(-time.Hour))
	writeSignal("ssdp", "VendorNewer", 0.9, now) // same confidence, more recent

	resolveOnce := func() string {
		t.Helper()
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback()
		fields, err := db.resolveCanonicalFields(tx, deviceID)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		return fields["vendor"].value
	}

	want := resolveOnce()
	if want != "VendorNewer" {
		t.Fatalf("equal-confidence tie winner = %q, want most-recent 'VendorNewer'", want)
	}
	// Repeated resolutions must be stable (deterministic).
	for i := 0; i < 20; i++ {
		if got := resolveOnce(); got != want {
			t.Fatalf("canonical resolution nondeterministic: iter %d got %q, want %q", i, got, want)
		}
	}
}
