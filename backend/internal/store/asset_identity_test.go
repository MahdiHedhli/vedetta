package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func issueTestCacheDeliveryEpoch(t *testing.T, db *DB, sensorID string) string {
	t.Helper()
	epoch, err := db.IssueARPCacheDeliveryEpoch(sensorID)
	if err != nil {
		t.Fatalf("issue cache delivery epoch for %s: %v", sensorID, err)
	}
	return epoch
}

func observeAsset(t *testing.T, db *DB, at time.Time, sensor, segment, ip, mac, hostname string,
	evidence ...discovery.IdentityEvidence) string {
	t.Helper()
	_, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Hostname: hostname,
			DiscoverySource: "passive_dhcp", IdentityEvidence: evidence,
		},
		Segment: segment, SensorID: sensor, ObservedAt: at,
	})
	if err != nil {
		t.Fatalf("observe %s/%s: %v", segment, ip, err)
	}
	var id string
	if err := db.QueryRow(`SELECT device_id FROM device_address_history
		WHERE address_type='ip' AND address_value=? AND segment=? AND sensor_id=?
		  AND valid_from <= ? AND (valid_until IS NULL OR ? < valid_until)
		ORDER BY valid_from DESC LIMIT 1`, ip, segment, sensor, at, at).Scan(&id); err != nil {
		t.Fatalf("read observed device id: %v", err)
	}
	canonical, err := db.CanonicalDeviceID(context.Background(), id)
	if err != nil {
		t.Fatalf("canonical id: %v", err)
	}
	return canonical
}

func evidence(kind, value string, confidence float64) discovery.IdentityEvidence {
	return discovery.IdentityEvidence{Type: kind, Value: value, Source: "passive_dhcp", Confidence: confidence, Sensitive: true}
}

func TestObserveDeviceARPCacheConflictIsPreservedDeduplicatedAndCannotOverrideLiveBinding(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	liveMAC := "00:00:5E:00:53:21"
	cacheMAC := "00:00:5E:00:53:22"
	ip := "192.0.2.21"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.21", liveMAC, "synthetic-live-host")

	type binding struct {
		ID, DeviceID, Source string
		FirstSeen, LastSeen  time.Time
		ValidFrom            time.Time
		ValidUntil           sql.NullTime
		Confidence           float64
	}
	readStrongBinding := func() binding {
		t.Helper()
		var got binding
		if err := db.QueryRow(`SELECT binding_id, device_id, first_seen, last_seen, valid_from,
			valid_until, evidence_source, confidence FROM device_address_history
			WHERE address_type='ip' AND address_value=? AND segment='lan' AND sensor_id='sensor-a'
			  AND valid_until IS NULL`, ip).Scan(&got.ID, &got.DeviceID, &got.FirstSeen, &got.LastSeen,
			&got.ValidFrom, &got.ValidUntil, &got.Source, &got.Confidence); err != nil {
			t.Fatal(err)
		}
		return got
	}
	strongBefore := readStrongBinding()

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: cacheMAC, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("observe conflicting ARP cache mapping: %v", err)
	}
	if !created {
		t.Fatal("conflicting cache observation was silently dropped instead of preserved provisionally")
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("devices after cache conflict = %d, want live + provisional", got)
	}

	var provisionalID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE discovery_method='arp_cache' AND ip_address=?`, ip).
		Scan(&provisionalID); err != nil {
		t.Fatalf("read preserved provisional observation: %v", err)
	}
	if provisionalID == deviceID {
		t.Fatal("cache conflict attached to the live owner")
	}

	// A repeated delivery is also what Core sees after a sensor restart: the
	// source-side snapshot is gone, but durable store dedupe must still win.
	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: cacheMAC, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(2 * time.Hour),
	})
	if err != nil || created {
		t.Fatalf("repeat cache delivery: created=%v err=%v, want deduplicated refresh", created, err)
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("repeat cache delivery multiplied devices: got %d", got)
	}
	var repeatedID string
	var provisionalLastSeen time.Time
	if err := db.QueryRow(`SELECT device_id, last_seen FROM devices WHERE discovery_method='arp_cache' AND ip_address=?`, ip).
		Scan(&repeatedID, &provisionalLastSeen); err != nil {
		t.Fatal(err)
	}
	if repeatedID != provisionalID || !provisionalLastSeen.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("repeat did not refresh exact provisional edge: id=%q last_seen=%s", repeatedID, provisionalLastSeen)
	}

	var gotMAC string
	var lastSeen time.Time
	if err := db.QueryRow(`SELECT mac_address, last_seen FROM devices WHERE device_id = ?`, deviceID).Scan(&gotMAC, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if gotMAC != liveMAC || !lastSeen.Equal(base) {
		t.Fatalf("cache conflict refreshed/overwrote live owner: mac=%q last_seen=%s", gotMAC, lastSeen)
	}
	strongAfter := readStrongBinding()
	if !reflect.DeepEqual(strongAfter, strongBefore) {
		t.Fatalf("cache conflict mutated strong address interval: before=%+v after=%+v", strongBefore, strongAfter)
	}
	if strongAfter.DeviceID != deviceID || strongAfter.Source != "passive_dhcp" || strongAfter.Confidence <= arpCacheIdentityConfidence {
		t.Fatalf("unexpected strong owner fixture: %+v", strongAfter)
	}
	var cacheEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence
		WHERE device_id=? AND evidence_type='mac' AND source='arp_cache'`, provisionalID).Scan(&cacheEvidence); err != nil {
		t.Fatal(err)
	}
	if cacheEvidence != 1 {
		t.Fatalf("cache replay persisted %d weak MAC rows, want exactly one", cacheEvidence)
	}
	var provisionalMAC string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE device_id=?`, provisionalID).Scan(&provisionalMAC); err != nil {
		t.Fatal(err)
	}
	if provisionalMAC != "" {
		t.Fatalf("cache MAC became canonical: %q", provisionalMAC)
	}
	resolved, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(2 * time.Hour), MACAddress: cacheMAC, Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.DeviceID != "" {
		t.Fatalf("weak cache MAC resolved a canonical identity: %+v", resolved)
	}
}

func TestObserveDeviceARPCacheOldSameMACCannotRegressNewerLiveLocation(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 13, 0, 0, 0, time.UTC)
	mac := "00:00:5E:00:53:31"
	oldIP := "192.0.2.31"
	newLANIP := "192.0.2.32"
	currentIP := "198.51.100.31"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", oldIP, mac, "mobile-device")
	if got := observeAsset(t, db, base.Add(2*time.Hour), "sensor-a", "lan", newLANIP, mac, "mobile-device"); got != deviceID {
		t.Fatalf("live LAN move split device: got %q want %q", got, deviceID)
	}
	if got := observeAsset(t, db, base.Add(3*time.Hour), "sensor-a", "secure", currentIP, mac, "mobile-device"); got != deviceID {
		t.Fatalf("live move split device: got %q want %q", got, deviceID)
	}

	type liveState struct {
		IP, Segment, NetworkIP, NetworkSensor string
		LastSeen, NetworkLastSeen             time.Time
	}
	readLiveState := func() liveState {
		t.Helper()
		var got liveState
		if err := db.QueryRow(`SELECT d.ip_address, d.segment, d.last_seen,
			n.ip_address, n.sensor_id, n.last_seen
			FROM devices d JOIN device_networks n ON n.device_id=d.device_id AND n.segment='lan'
			WHERE d.device_id=?`, deviceID).Scan(&got.IP, &got.Segment, &got.LastSeen,
			&got.NetworkIP, &got.NetworkSensor, &got.NetworkLastSeen); err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := readLiveState()
	if before.IP != currentIP || before.Segment != "secure" || before.NetworkIP != newLANIP {
		t.Fatalf("new live location fixture is not current: %+v", before)
	}
	type addressState struct {
		ID, Owner, Source string
		First, Last, From time.Time
		Until             sql.NullTime
		Confidence        float64
	}
	readOldStrongAddress := func() addressState {
		t.Helper()
		var got addressState
		if err := db.QueryRow(`SELECT binding_id, device_id, evidence_source, first_seen,
			last_seen, valid_from, valid_until, confidence FROM device_address_history
			WHERE address_type='ip' AND address_value=? AND segment='lan' AND sensor_id='sensor-a'
			ORDER BY valid_from LIMIT 1`, oldIP).Scan(&got.ID, &got.Owner, &got.Source, &got.First,
			&got.Last, &got.From, &got.Until, &got.Confidence); err != nil {
			t.Fatal(err)
		}
		return got
	}
	addressBefore := readOldStrongAddress()

	created, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: oldIP, MACAddress: mac, DiscoverySource: "arp_cache"},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(4 * time.Hour),
	})
	if err != nil || !created {
		t.Fatalf("preserve stale same-MAC edge provisionally: created=%v err=%v", created, err)
	}
	after := readLiveState()
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("old cache edge regressed current live projection/network: before=%+v after=%+v", before, after)
	}
	addressAfter := readOldStrongAddress()
	if !reflect.DeepEqual(addressAfter, addressBefore) {
		t.Fatalf("old cache edge mutated strong temporal ownership: before=%+v after=%+v", addressBefore, addressAfter)
	}
	var provisionalID, canonicalMAC string
	if err := db.QueryRow(`SELECT device_id, mac_address FROM devices
		WHERE discovery_method='arp_cache' AND ip_address=? AND segment='lan'`, oldIP).
		Scan(&provisionalID, &canonicalMAC); err != nil {
		t.Fatalf("read old-edge provisional device: %v", err)
	}
	if provisionalID == deviceID || canonicalMAC != "" {
		t.Fatalf("old edge attached/canonicalized: provisional=%q live=%q mac=%q", provisionalID, deviceID, canonicalMAC)
	}
}

func TestObserveDeviceARPCacheDoesNotRegressLiveCanonicalProjection(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	ip := "192.0.2.64"
	mac := "00:00:5E:00:53:64"
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Vendor: "Apple", OpenPorts: []int{443},
			DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
	})
	if err != nil || !created {
		t.Fatalf("create live device: created=%v err=%v", created, err)
	}
	type projection struct {
		DisplayName, DiscoveryMethod, MAC, Vendor, Model, DeviceType, RiskCategory, OpenPorts string
		LastSeen                                                                              time.Time
	}
	readProjection := func() projection {
		t.Helper()
		var p projection
		if err := db.QueryRow(`SELECT display_name, discovery_method, mac_address, vendor, model,
			device_type, risk_category, open_ports, last_seen FROM devices WHERE ip_address=?`, ip).
			Scan(&p.DisplayName, &p.DiscoveryMethod, &p.MAC, &p.Vendor, &p.Model,
				&p.DeviceType, &p.RiskCategory, &p.OpenPorts, &p.LastSeen); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := readProjection()
	if before.DisplayName != "Apple 53:64" || before.DiscoveryMethod != "passive_dhcp" {
		t.Fatalf("live fixture did not establish MAC-derived display/provenance: %+v", before)
	}
	var signalsBefore int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_signals`).Scan(&signalsBefore); err != nil {
		t.Fatal(err)
	}

	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Hostname: "crafted-router", Vendor: "D-Link",
			Model: "DIR-850L", FriendlyName: "crafted cache label", OpenPorts: []int{23},
			Services: []string{"_telnet._tcp"}, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Hour),
	})
	if err != nil || created {
		t.Fatalf("observe matching cache row: created=%v err=%v", created, err)
	}
	after := readProjection()
	if after.DisplayName != before.DisplayName || after.DiscoveryMethod != before.DiscoveryMethod ||
		after.MAC != before.MAC || after.Vendor != before.Vendor || after.Model != before.Model ||
		after.DeviceType != before.DeviceType || after.RiskCategory != before.RiskCategory ||
		after.OpenPorts != before.OpenPorts {
		t.Fatalf("cache row regressed canonical projection: before=%+v after=%+v", before, after)
	}
	if !after.LastSeen.Equal(base.Add(time.Hour)) {
		t.Fatalf("cache temporal observation not retained: last_seen=%s", after.LastSeen)
	}
	var signalsAfter int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_signals`).Scan(&signalsAfter); err != nil {
		t.Fatal(err)
	}
	if signalsAfter != signalsBefore {
		t.Fatalf("cache row changed signal count from %d to %d", signalsBefore, signalsAfter)
	}
}

func TestObserveDeviceARPCacheUsesWeakIdentityConfidence(t *testing.T) {
	db := newCorrelationDB(t)
	at := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "198.51.100.23", MACAddress: "00:00:5E:00:53:23",
			Hostname: "router", Vendor: "D-Link", Model: "DIR-850L", FriendlyName: "crafted cache router",
			OpenPorts: []int{23}, Services: []string{"_http._tcp"},
			IdentityEvidence: []discovery.IdentityEvidence{{
				Type: "dhcp_client_id", Value: "crafted-cache-id", Source: "passive_dhcp", Confidence: 0.99,
			}},
			Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
	})
	if err != nil {
		t.Fatalf("observe ARP cache mapping: %v", err)
	}
	if !created {
		t.Fatal("first ARP cache mapping should create a provisional device")
	}

	rows, err := db.Query(`SELECT address_type, confidence FROM device_address_history
		WHERE evidence_source='arp_cache' ORDER BY address_type`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]float64{}
	for rows.Next() {
		var kind string
		var confidence float64
		if err := rows.Scan(&kind, &confidence); err != nil {
			t.Fatal(err)
		}
		seen[kind] = confidence
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"ip", "mac"} {
		if got := seen[kind]; got != arpCacheIdentityConfidence {
			t.Errorf("arp_cache %s binding confidence = %v, want %v", kind, got, arpCacheIdentityConfidence)
		}
	}
	var evidenceConfidence float64
	if err := db.QueryRow(`SELECT confidence FROM device_identity_evidence
		WHERE evidence_type='mac' AND source='arp_cache'`).Scan(&evidenceConfidence); err != nil {
		t.Fatal(err)
	}
	if evidenceConfidence != arpCacheIdentityConfidence {
		t.Fatalf("arp_cache MAC evidence confidence = %v, want %v", evidenceConfidence, arpCacheIdentityConfidence)
	}
	var canonicalMAC, hostname, vendor, model, friendlyName, deviceType, riskCategory, openPorts, services string
	if err := db.QueryRow(`SELECT mac_address, hostname, vendor, model, friendly_name, device_type, risk_category,
		open_ports, services FROM devices WHERE ip_address='198.51.100.23'`).
		Scan(&canonicalMAC, &hostname, &vendor, &model, &friendlyName, &deviceType, &riskCategory, &openPorts, &services); err != nil {
		t.Fatal(err)
	}
	if canonicalMAC != "" || hostname != "" || vendor != "" || model != "" || friendlyName != "" ||
		deviceType != "" || riskCategory != "" || openPorts != "[]" || services != "[]" {
		t.Fatalf("cache-only payload became canonical/fingerprint input: mac=%q hostname=%q vendor=%q model=%q friendly=%q type=%q risk=%q ports=%q services=%q",
			canonicalMAC, hostname, vendor, model, friendlyName, deviceType, riskCategory, openPorts, services)
	}
	var authoritativeIdentities int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identities WHERE id_type IN ('mac','hostname')`).Scan(&authoritativeIdentities); err != nil {
		t.Fatal(err)
	}
	if authoritativeIdentities != 0 {
		t.Fatalf("cache-only payload created %d authoritative legacy identities", authoritativeIdentities)
	}
	var craftedEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE evidence_type='dhcp_client_id'`).Scan(&craftedEvidence); err != nil {
		t.Fatal(err)
	}
	if craftedEvidence != 0 {
		t.Fatalf("cache-only payload persisted %d crafted stable identity rows", craftedEvidence)
	}
	var canonicalSignals int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_signals`).Scan(&canonicalSignals); err != nil {
		t.Fatal(err)
	}
	if canonicalSignals != 0 {
		t.Fatalf("cache-only payload created %d canonical signal candidates", canonicalSignals)
	}
	resolved, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: at, MACAddress: "00:00:5E:00:53:23", Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.DeviceID != "" {
		t.Fatalf("weak cache MAC resolved as authoritative identity: %+v", resolved)
	}
}

func TestObserveDeviceARPCacheConcurrentReplayCreatesOneProvisionalDevice(t *testing.T) {
	db := newCorrelationDB(t)
	at := time.Date(2026, 7, 15, 11, 30, 0, 0, time.UTC)
	observation := DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "198.51.100.24", MACAddress: "00:00:5E:00:53:24",
			Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
	}
	type result struct {
		created bool
		err     error
	}
	const reporters = 12
	start := make(chan struct{})
	results := make(chan result, reporters)
	for i := 0; i < reporters; i++ {
		go func() {
			<-start
			created, err := db.ObserveDevice(observation)
			results <- result{created: created, err: err}
		}()
	}
	close(start)
	createdCount := 0
	for i := 0; i < reporters; i++ {
		got := <-results
		if got.err != nil {
			t.Fatalf("concurrent cache replay %d: %v", i, got.err)
		}
		if got.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent cache deliveries reported %d creations, want 1", createdCount)
	}
	if got := countDevices(t, db); got != 1 {
		t.Fatalf("concurrent cache deliveries persisted %d devices, want 1", got)
	}
	var evidenceCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence
		WHERE evidence_type='mac' AND source='arp_cache'`).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 1 {
		t.Fatalf("concurrent cache deliveries persisted %d MAC evidence rows, want 1", evidenceCount)
	}
}

func TestObserveDeviceARPCacheProxyARPRemainsProvisionalUntilLiveCorroboration(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	proxyMAC := "00:18:0A:00:53:44" // Cisco/router OUI: must not fingerprint cache-only IPs.
	for _, ip := range []string{"192.0.2.41", "192.0.2.42"} {
		created, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: proxyMAC, Status: "observed", DiscoverySource: " ARP_CACHE ",
			},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
		})
		if err != nil {
			t.Fatalf("observe proxy cache row %s: %v", ip, err)
		}
		if !created {
			t.Fatalf("proxy cache IP %s did not remain a separate provisional device", ip)
		}
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("proxy ARP collapsed two IPs into %d devices, want 2", got)
	}
	rows, err := db.Query(`SELECT ip_address, mac_address, vendor, device_type, risk_category FROM devices ORDER BY ip_address`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip, mac, vendor, deviceType, risk string
		if err := rows.Scan(&ip, &mac, &vendor, &deviceType, &risk); err != nil {
			t.Fatal(err)
		}
		if mac != "" || vendor != "" || deviceType != "" || risk != "" {
			t.Fatalf("proxy cache row %s became canonical: mac=%q vendor=%q type=%q risk=%q", ip, mac, vendor, deviceType, risk)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var legacyMACs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identities WHERE id_type='mac'`).Scan(&legacyMACs); err != nil {
		t.Fatal(err)
	}
	if legacyMACs != 0 {
		t.Fatalf("proxy cache rows created %d authoritative MAC identities", legacyMACs)
	}

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "192.0.2.41", MACAddress: proxyMAC, DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("live corroboration: %v", err)
	}
	if created {
		t.Fatal("live corroboration split the provisional device instead of promoting it")
	}
	var promotedMAC, untouchedMAC string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE ip_address='192.0.2.41'`).Scan(&promotedMAC); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE ip_address='192.0.2.42'`).Scan(&untouchedMAC); err != nil {
		t.Fatal(err)
	}
	if normalizeAddress("mac", promotedMAC) != normalizeAddress("mac", proxyMAC) || untouchedMAC != "" {
		t.Fatalf("live corroboration promoted wrong records: promoted=%q untouched=%q", promotedMAC, untouchedMAC)
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("live corroboration changed device count to %d, want 2", got)
	}
}

func TestObserveDeviceARPCacheDifferentMACDoesNotAttachToStaleCanonicalIP(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	ip := "203.0.113.61"
	liveMAC := "00:00:5E:00:53:61"
	cacheMAC := "00:00:5E:00:53:62"
	liveID := observeAsset(t, db, base, "sensor-a", "lan", ip, liveMAC, "old-owner")
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: cacheMAC, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(25 * time.Hour),
	})
	if err != nil {
		t.Fatalf("observe cache row after recency window: %v", err)
	}
	if !created {
		t.Fatal("different weak MAC attached to stale canonical-IP owner")
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("stale IP reuse device count = %d, want 2", got)
	}
	var oldMAC string
	var oldLastSeen time.Time
	if err := db.QueryRow(`SELECT mac_address, last_seen FROM devices WHERE device_id=?`, liveID).Scan(&oldMAC, &oldLastSeen); err != nil {
		t.Fatal(err)
	}
	if normalizeAddress("mac", oldMAC) != normalizeAddress("mac", liveMAC) || !oldLastSeen.Equal(base) {
		t.Fatalf("weak cache row mutated old owner: mac=%q last_seen=%s", oldMAC, oldLastSeen)
	}
	var provisionalMAC string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE device_id<>?`, liveID).Scan(&provisionalMAC); err != nil {
		t.Fatal(err)
	}
	if provisionalMAC != "" {
		t.Fatalf("stale cache replacement became canonical MAC %q", provisionalMAC)
	}
}

func TestObserveDeviceStrongMACPromotesExactCacheProvisionalAfterIPReuse(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 14, 0, 0, 0, time.UTC)
	ip := "192.0.2.91"
	macA := "00:00:5E:00:53:91"
	macB := "00:00:5E:00:53:92"
	observeCache := func(mac string, at time.Time) string {
		t.Helper()
		created, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
			},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
		})
		if err != nil || !created {
			t.Fatalf("cache %s: created=%v err=%v", mac, created, err)
		}
		key, err := db.identityHMACKeyCached()
		if err != nil {
			t.Fatal(err)
		}
		var id string
		if err := db.QueryRow(`SELECT device_id FROM device_identity_evidence
			WHERE evidence_type='mac' AND value_hmac=? AND source='arp_cache'`,
			identityValueHMAC(key, "mac", mac)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	idA := observeCache(macA, base)
	idB := observeCache(macB, base.Add(time.Minute))
	if idA == idB || countDevices(t, db) != 2 {
		t.Fatalf("IP reuse cache fixture collapsed: A=%q B=%q", idA, idB)
	}

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: macB, Hostname: "replacement-device",
			DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(2 * time.Minute),
	})
	if err != nil || created {
		t.Fatalf("strong corroboration: created=%v err=%v", created, err)
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("strong corroboration changed device count to %d, want 2", got)
	}
	var promotedMAC, promotedMethod, untouchedMAC, untouchedMethod string
	if err := db.QueryRow(`SELECT mac_address, discovery_method FROM devices WHERE device_id=?`, idB).
		Scan(&promotedMAC, &promotedMethod); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT mac_address, discovery_method FROM devices WHERE device_id=?`, idA).
		Scan(&untouchedMAC, &untouchedMethod); err != nil {
		t.Fatal(err)
	}
	if normalizeAddress("mac", promotedMAC) != normalizeAddress("mac", macB) || promotedMethod != "passive_dhcp" {
		t.Fatalf("exact MAC-B provisional was not promoted: mac=%q method=%q", promotedMAC, promotedMethod)
	}
	if untouchedMAC != "" || untouchedMethod != "arp_cache" {
		t.Fatalf("MAC-A IP fallback was promoted incorrectly: mac=%q method=%q", untouchedMAC, untouchedMethod)
	}
}

func TestObserveDeviceDelayedStrongObservationPromotesCacheProvenance(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC)
	ip := "198.51.100.93"
	mac := "00:00:5E:00:53:93"
	cacheAt := base.Add(time.Minute)
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: cacheAt,
	})
	if err != nil || !created {
		t.Fatalf("cache provisional: created=%v err=%v", created, err)
	}
	var deviceID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address=?`, ip).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}

	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Hostname: "delayed-live-device",
			OpenPorts: []int{443}, Services: []string{"_https._tcp"},
			DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
	})
	if err != nil || created {
		t.Fatalf("delayed strong corroboration: created=%v err=%v", created, err)
	}
	var firstSeen, lastSeen time.Time
	var canonicalMAC, method, display, ports, services string
	if err := db.QueryRow(`SELECT first_seen, last_seen, mac_address, discovery_method,
		display_name, open_ports, services FROM devices WHERE device_id=?`, deviceID).
		Scan(&firstSeen, &lastSeen, &canonicalMAC, &method, &display, &ports, &services); err != nil {
		t.Fatal(err)
	}
	if !firstSeen.Equal(base) || !lastSeen.Equal(cacheAt) {
		t.Fatalf("delayed promotion regressed temporal bounds: first=%s last=%s", firstSeen, lastSeen)
	}
	if normalizeAddress("mac", canonicalMAC) != normalizeAddress("mac", mac) || method != "passive_dhcp" ||
		display == ip || ports != "[443]" || services != `["_https._tcp"]` {
		t.Fatalf("delayed promotion incomplete: mac=%q method=%q display=%q ports=%s services=%s",
			canonicalMAC, method, display, ports, services)
	}
	var source string
	var confidence float64
	var validFrom time.Time
	if err := db.QueryRow(`SELECT source, confidence, valid_from FROM device_identity_evidence
		WHERE device_id=? AND evidence_type='mac'`, deviceID).Scan(&source, &confidence, &validFrom); err != nil {
		t.Fatal(err)
	}
	if source != "passive_dhcp" || confidence != 0.95 || !validFrom.Equal(base) {
		t.Fatalf("promoted MAC provenance = source=%q confidence=%v valid_from=%s", source, confidence, validFrom)
	}
}

func TestObserveDeviceNativeICMPAndScopedARPCacheFuseActiveFirst(t *testing.T) {
	db := newCorrelationDB(t)
	epoch := issueTestCacheDeliveryEpoch(t, db, "windows-sensor")
	base := time.Date(2026, 7, 15, 16, 0, 0, 0, time.UTC)
	ip := "203.0.113.94"
	mac := "00:00:5E:00:53:94"
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource,
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: base,
	})
	if err != nil || !created {
		t.Fatalf("native ICMP observation: created=%v err=%v", created, err)
	}
	var liveID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address=?`, ip).Scan(&liveID); err != nil {
		t.Fatal(err)
	}
	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: base.Add(time.Minute),
		DeliveryEpoch: epoch, DeliverySequence: 1,
	})
	if err != nil || created {
		t.Fatalf("scoped cache corroboration: created=%v err=%v", created, err)
	}
	assertNativeARPFusion(t, db, liveID, mac)
}

func TestObserveDeviceNativeICMPAndScopedARPCacheFuseCacheFirst(t *testing.T) {
	db := newCorrelationDB(t)
	epoch := issueTestCacheDeliveryEpoch(t, db, "windows-sensor")
	base := time.Date(2026, 7, 15, 17, 0, 0, 0, time.UTC)
	ip := "203.0.113.95"
	mac := "00:00:5E:00:53:95"
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: base,
		DeliveryEpoch: epoch, DeliverySequence: 1,
	})
	if err != nil || !created {
		t.Fatalf("cache provisional: created=%v err=%v", created, err)
	}
	var provisionalID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address=?`, ip).Scan(&provisionalID); err != nil {
		t.Fatal(err)
	}
	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource,
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: base.Add(time.Minute),
	})
	if err != nil || created {
		t.Fatalf("native ICMP corroboration: created=%v err=%v", created, err)
	}
	assertNativeARPFusion(t, db, provisionalID, mac)
}

func TestObserveDeviceNativeICMPAndLegacyARPCacheCacheFirstFailsClosedOnCompetingMACs(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 17, 30, 0, 0, time.UTC)
	ip := "203.0.113.96"
	macs := []string{"00:00:5E:00:53:96", "00:00:5E:00:53:97"}
	for _, mac := range macs {
		created, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
			},
			Segment: "lan", SensorID: "windows-sensor", ObservedAt: base,
		})
		if err != nil || !created {
			t.Fatalf("cache provisional %s: created=%v err=%v", mac, created, err)
		}
	}
	if got := countDevices(t, db); got != 2 {
		t.Fatalf("competing cache fixture has %d devices, want 2", got)
	}

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource,
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: base.Add(time.Minute),
	})
	if err != nil || created {
		t.Fatalf("ambiguous native ICMP observation: created=%v err=%v", created, err)
	}
	var canonicalMACs, fusedEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE COALESCE(mac_address, '') != ''`).Scan(&canonicalMACs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source = ?`, arpLiveFusionSource).Scan(&fusedEvidence); err != nil {
		t.Fatal(err)
	}
	if canonicalMACs != 0 || fusedEvidence != 0 {
		t.Fatalf("competing cache MACs were fused: canonical=%d fused_evidence=%d", canonicalMACs, fusedEvidence)
	}

	// Replaying one side of the same-snapshot conflict after the liveness update
	// must not bypass the cache-first ambiguity veto through the active-first path.
	if _, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: macs[1], Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: base,
	}); err != nil {
		t.Fatalf("replay competing cache edge: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE COALESCE(mac_address, '') != ''`).Scan(&canonicalMACs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source = ?`, arpLiveFusionSource).Scan(&fusedEvidence); err != nil {
		t.Fatal(err)
	}
	if canonicalMACs != 0 || fusedEvidence != 0 {
		t.Fatalf("cache replay bypassed ambiguity veto: canonical=%d fused_evidence=%d", canonicalMACs, fusedEvidence)
	}
}

func TestObserveDeviceNativeICMPRefusesLatestBlankARPCacheState(t *testing.T) {
	db := newCorrelationDB(t)
	epoch := issueTestCacheDeliveryEpoch(t, db, "windows-sensor")
	base := time.Date(2026, 7, 15, 17, 40, 0, 0, time.UTC)
	ip := "203.0.113.97"
	macA := "00:00:5E:00:53:97"
	macB := "00:00:5E:00:53:A7"
	observe := func(at time.Time, source, gotMAC string, sequence uint64) {
		t.Helper()
		if _, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: gotMAC, Status: "observed", DiscoverySource: source,
			},
			Segment: "lan", SensorID: "windows-sensor", ObservedAt: at,
			DeliveryEpoch: epoch, DeliverySequence: sequence,
		}); err != nil {
			t.Fatalf("observe %s MAC=%q: %v", source, gotMAC, err)
		}
	}

	observe(base, "arp_cache", macA, 1)
	observe(base.Add(time.Minute), "arp_cache", "", 2) // proxy/conflicting latest cache state
	observe(base.Add(2*time.Minute), nativeICMPBoundSource, "", 0)

	var canonicalMACs, fusedEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE COALESCE(mac_address, '') != ''`).Scan(&canonicalMACs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source = ?`, arpLiveFusionSource).Scan(&fusedEvidence); err != nil {
		t.Fatal(err)
	}
	if canonicalMACs != 0 || fusedEvidence != 0 {
		t.Fatalf("blank proxy state resurrected stale MAC: canonical=%d fused_evidence=%d", canonicalMACs, fusedEvidence)
	}

	// A strictly newer unique cache transition is current evidence and restores
	// active-first fusion instead of making the blank veto permanent.
	observe(base.Add(3*time.Minute), "arp_cache", macB, 3)
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ? AND discovery_method = ?`,
		normalizeAddress("mac", macB), arpLiveFusionSource).Scan(&canonicalMACs); err != nil {
		t.Fatal(err)
	}
	if canonicalMACs != 1 {
		t.Fatalf("newer unique cache state did not recover fusion: got %d joined devices", canonicalMACs)
	}
	var state, macHMAC string
	if err := db.QueryRow(`SELECT state, mac_hmac FROM arp_cache_states
		WHERE sensor_id='windows-sensor' AND segment='lan' AND ip_address=?`, ip).Scan(&state, &macHMAC); err != nil {
		t.Fatal(err)
	}
	if state != arpCacheStateUnique || len(macHMAC) != 64 || macHMAC == macA || macHMAC == macB {
		t.Fatalf("latest ARP state leaked/raw or stale: state=%q hash=%q", state, macHMAC)
	}
}

func TestObserveDeviceBlankARPCacheVetoIsScopedAndSameTimeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		blankSensor  string
		blankSegment string
		blankAt      time.Duration
		wantFusion   bool
	}{
		{name: "same timestamp", blankSensor: "sensor-a", blankSegment: "lan", blankAt: 0, wantFusion: false},
		{name: "different sensor", blankSensor: "sensor-b", blankSegment: "lan", blankAt: time.Minute, wantFusion: true},
		{name: "different segment", blankSensor: "sensor-a", blankSegment: "iot", blankAt: time.Minute, wantFusion: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newCorrelationDB(t)
			epochA := issueTestCacheDeliveryEpoch(t, db, "sensor-a")
			epochBlank := epochA
			if tc.blankSensor != "sensor-a" {
				epochBlank = issueTestCacheDeliveryEpoch(t, db, tc.blankSensor)
			}
			base := time.Date(2026, 7, 15, 17, 50, 0, 0, time.UTC)
			ip := "198.51.100.197"
			mac := "00:00:5E:00:53:E7"
			if _, err := db.ObserveDevice(DeviceObservation{
				Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache"},
				Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
				DeliveryEpoch: epochA, DeliverySequence: 1,
			}); err != nil {
				t.Fatal(err)
			}
			blankSequence := uint64(1)
			if tc.blankSensor == "sensor-a" && tc.blankSegment == "lan" {
				// This is a valid later transition in the immutable delivery
				// stream, even though the wall-clock timestamp is unchanged.
				blankSequence = 2
			}
			if _, err := db.ObserveDevice(DeviceObservation{
				Host:    discovery.DiscoveredHost{IPAddress: ip, Status: "observed", DiscoverySource: "arp_cache"},
				Segment: tc.blankSegment, SensorID: tc.blankSensor, ObservedAt: base.Add(tc.blankAt),
				DeliveryEpoch: epochBlank, DeliverySequence: blankSequence,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ObserveDevice(DeviceObservation{
				Host:    discovery.DiscoveredHost{IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource},
				Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(2 * time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			var fused int
			if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ? AND discovery_method = ?`,
				normalizeAddress("mac", mac), arpLiveFusionSource).Scan(&fused); err != nil {
				t.Fatal(err)
			}
			if (fused == 1) != tc.wantFusion {
				t.Fatalf("fusion=%d, wantFusion=%v", fused, tc.wantFusion)
			}
		})
	}
}

func TestARPCacheStateRejectsDelayedPreBlankReportThenAllowsNewUniqueState(t *testing.T) {
	db := newCorrelationDB(t)
	epoch := issueTestCacheDeliveryEpoch(t, db, "sensor-a")
	base := time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)
	ip := "198.51.100.198"
	macA := "00:00:5E:00:53:E8"
	macB := "00:00:5E:00:53:F8"
	observe := func(at time.Time, source, mac string, sequence uint64) error {
		t.Helper()
		_, err := db.ObserveDevice(DeviceObservation{
			Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: source},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
			DeliveryEpoch: epoch, DeliverySequence: sequence,
		})
		return err
	}

	if err := observe(base, nativeICMPBoundSource, "", 0); err != nil {
		t.Fatal(err)
	}
	if err := observe(base.Add(2*time.Minute), "arp_cache", "", 2); err != nil {
		t.Fatal(err)
	}
	// Delivered later but observed before the blank transition. It is within the
	// live fusion window and would otherwise attach to the native device.
	if err := observe(base.Add(time.Minute), "arp_cache", macA, 1); !errors.Is(err, ErrARPCacheDeliveryStale) {
		t.Fatalf("delayed pre-blank delivery error=%v, want stale", err)
	}

	var fusedA int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, normalizeAddress("mac", macA)).Scan(&fusedA); err != nil {
		t.Fatal(err)
	}
	if fusedA != 0 {
		t.Fatal("delayed pre-blank MAC fused after a later ambiguous transition")
	}
	var state string
	var observedAt time.Time
	if err := db.QueryRow(`SELECT state, observed_at FROM arp_cache_states
		WHERE sensor_id='sensor-a' AND segment='lan' AND ip_address=?`, ip).Scan(&state, &observedAt); err != nil {
		t.Fatal(err)
	}
	if state != arpCacheStateAmbiguous || !observedAt.Equal(base.Add(2*time.Minute)) {
		t.Fatalf("delayed report changed latest state: state=%q at=%s", state, observedAt)
	}

	if err := observe(base.Add(3*time.Minute), "arp_cache", macB, 3); err != nil {
		t.Fatal(err)
	}
	var fusedB int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=? AND discovery_method=?`,
		normalizeAddress("mac", macB), arpLiveFusionSource).Scan(&fusedB); err != nil {
		t.Fatal(err)
	}
	if fusedB != 1 {
		t.Fatalf("new unique post-blank state did not fuse active-first: %d", fusedB)
	}
	if err := db.QueryRow(`SELECT state, observed_at FROM arp_cache_states
		WHERE sensor_id='sensor-a' AND segment='lan' AND ip_address=?`, ip).Scan(&state, &observedAt); err != nil {
		t.Fatal(err)
	}
	if state != arpCacheStateUnique || !observedAt.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("new unique state was not durable: state=%q at=%s", state, observedAt)
	}
}

func TestLegacyARPCacheStateSameTimestampConflictIsDeliveryOrderIndependent(t *testing.T) {
	for _, blankFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("blank-first-%t", blankFirst), func(t *testing.T) {
			db := newCorrelationDB(t)
			at := time.Date(2026, 7, 15, 18, 10, 0, 0, time.UTC)
			ip := "203.0.113.199"
			mac := "00:00:5E:00:53:F9"
			values := []string{mac, ""}
			if blankFirst {
				values[0], values[1] = values[1], values[0]
			}
			for _, value := range values {
				if _, err := db.ObserveDevice(DeviceObservation{
					Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: value, Status: "observed", DiscoverySource: "arp_cache"},
					Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
				}); err != nil {
					t.Fatal(err)
				}
			}
			var state, macHMAC string
			if err := db.QueryRow(`SELECT state, mac_hmac FROM arp_cache_states
				WHERE sensor_id='sensor-a' AND segment='lan' AND ip_address=?`, ip).Scan(&state, &macHMAC); err != nil {
				t.Fatal(err)
			}
			if state != arpCacheStateAmbiguous || macHMAC != "" {
				t.Fatalf("same-time conflict state=%q hash=%q, want ambiguous/empty", state, macHMAC)
			}
		})
	}
}

func TestARPCacheDeliveryGenerationIsImmutable(t *testing.T) {
	db := newCorrelationDB(t)
	sensorID := "sensor-immutable-generation"
	epoch := issueTestCacheDeliveryEpoch(t, db, sensorID)
	base := time.Date(2026, 7, 15, 18, 12, 0, 0, time.UTC)
	ip := "203.0.113.203"
	macA := "00:00:5E:00:53:A3"
	macB := "00:00:5E:00:53:B3"
	macC := "00:00:5E:00:53:C3"
	macD := "00:00:5E:00:53:D3"

	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource},
		Segment: "lan", SensorID: sensorID, ObservedAt: base,
	}); err != nil {
		t.Fatal(err)
	}
	first := DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: macA, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: sensorID, ObservedAt: base.Add(time.Minute),
		DeliveryEpoch: epoch, DeliverySequence: 1,
	}
	if _, err := db.ObserveDevice(first); err != nil {
		t.Fatalf("first immutable delivery: %v", err)
	}

	var firstState, firstHMAC string
	var firstObserved time.Time
	var firstOrder, firstSequence int64
	if err := db.QueryRow(`SELECT state, mac_hmac, observed_at,
		delivery_epoch_order, delivery_sequence FROM arp_cache_states
		WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&firstState, &firstHMAC, &firstObserved, &firstOrder, &firstSequence); err != nil {
		t.Fatal(err)
	}
	if firstState != arpCacheStateUnique || len(firstHMAC) != 64 || firstOrder <= 0 || firstSequence != 1 {
		t.Fatalf("first delivery state=%q hash=%q order=%d sequence=%d", firstState, firstHMAC, firstOrder, firstSequence)
	}
	// Exact retries are idempotent, including after the live-fusion projection
	// completed but its HTTP response might have been lost.
	if _, err := db.ObserveDevice(first); err != nil {
		t.Fatalf("exact immutable replay: %v", err)
	}

	mutations := []struct {
		name string
		mac  string
		at   time.Time
	}{
		{name: "different MAC", mac: macB, at: first.ObservedAt},
		{name: "blank state", mac: "", at: first.ObservedAt},
		{name: "different timestamp", mac: macA, at: first.ObservedAt.Add(time.Second)},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := first
			changed.Host.MACAddress = mutation.mac
			changed.ObservedAt = mutation.at
			if _, err := db.ObserveDevice(changed); !errors.Is(err, ErrARPCacheDeliveryMutation) {
				t.Fatalf("changed replay error=%v, want ErrARPCacheDeliveryMutation", err)
			}
		})
	}

	var gotState, gotHMAC string
	var gotObserved time.Time
	var gotOrder, gotSequence int64
	if err := db.QueryRow(`SELECT state, mac_hmac, observed_at,
		delivery_epoch_order, delivery_sequence FROM arp_cache_states
		WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&gotState, &gotHMAC, &gotObserved, &gotOrder, &gotSequence); err != nil {
		t.Fatal(err)
	}
	if gotState != firstState || gotHMAC != firstHMAC || !gotObserved.Equal(firstObserved) ||
		gotOrder != firstOrder || gotSequence != firstSequence {
		t.Fatalf("changed replay mutated ledger: before=%q/%q/%s/%d/%d after=%q/%q/%s/%d/%d",
			firstState, firstHMAC, firstObserved, firstOrder, firstSequence,
			gotState, gotHMAC, gotObserved, gotOrder, gotSequence)
	}
	var macBRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, normalizeAddress("mac", macB)).Scan(&macBRows); err != nil {
		t.Fatal(err)
	}
	if macBRows != 0 {
		t.Fatalf("changed duplicate created %d MAC-B projections", macBRows)
	}

	// A real later transition advances the sequence instead of mutating the
	// immutable generation.
	next := first
	next.Host.MACAddress = macB
	next.ObservedAt = base.Add(2 * time.Minute)
	next.DeliverySequence = 2
	if _, err := db.ObserveDevice(next); err != nil {
		t.Fatalf("next immutable delivery: %v", err)
	}
	if err := db.QueryRow(`SELECT mac_hmac, observed_at, delivery_sequence
		FROM arp_cache_states WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&gotHMAC, &gotObserved, &gotSequence); err != nil {
		t.Fatal(err)
	}
	if gotHMAC == firstHMAC || !gotObserved.Equal(next.ObservedAt) || gotSequence != 2 {
		t.Fatalf("new sequence did not advance ledger: hash=%q at=%s sequence=%d", gotHMAC, gotObserved, gotSequence)
	}

	// Once sequence 2 exists, even a changed replay of sequence 1 must stop
	// before creating provisional cache evidence.
	staleSequence := first
	staleSequence.Host.MACAddress = macC
	if _, err := db.ObserveDevice(staleSequence); !errors.Is(err, ErrARPCacheDeliveryStale) {
		t.Fatalf("stale sequence error=%v, want ErrARPCacheDeliveryStale", err)
	}

	// Activating a later Core-issued process epoch also makes every payload from
	// the retired epoch terminal, regardless of its sequence number.
	newEpoch := issueTestCacheDeliveryEpoch(t, db, sensorID)
	newProcess := next
	newProcess.DeliveryEpoch = newEpoch
	newProcess.DeliverySequence = 1
	newProcess.ObservedAt = base.Add(3 * time.Minute)
	if _, err := db.ObserveDevice(newProcess); err != nil {
		t.Fatalf("activate next process epoch: %v", err)
	}
	for i := 0; i < 12; i++ {
		_ = issueTestCacheDeliveryEpoch(t, db, sensorID)
	}
	var retainedHistory, pendingCandidates int
	if err := db.QueryRow(`SELECT COUNT(*) FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND delivery_epoch=? AND ever_activated_at IS NOT NULL`, sensorID, epoch).
		Scan(&retainedHistory); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND activated_at IS NULL AND ever_activated_at IS NULL`, sensorID).
		Scan(&pendingCandidates); err != nil {
		t.Fatal(err)
	}
	if retainedHistory != 1 || pendingCandidates > 8 {
		t.Fatalf("epoch retention history/pending=%d/%d, want retired history and at most 8 pending", retainedHistory, pendingCandidates)
	}
	retiredEpoch := first
	retiredEpoch.Host.MACAddress = macD
	retiredEpoch.DeliverySequence = 3
	retiredEpoch.ObservedAt = base.Add(4 * time.Minute)
	if _, err := db.ObserveDevice(retiredEpoch); !errors.Is(err, ErrARPCacheDeliveryStale) {
		t.Fatalf("retired epoch error=%v, want ErrARPCacheDeliveryStale", err)
	}
	var staleRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address IN (?, ?)`,
		normalizeAddress("mac", macC), normalizeAddress("mac", macD)).Scan(&staleRows); err != nil {
		t.Fatal(err)
	}
	if staleRows != 0 {
		t.Fatalf("stale deliveries created %d identity projections", staleRows)
	}
}

func TestARPCacheDeliveryGenerationConcurrentFirstWriterWins(t *testing.T) {
	db := newCorrelationDB(t)
	sensorID := "sensor-concurrent-generation"
	epoch := issueTestCacheDeliveryEpoch(t, db, sensorID)
	at := time.Date(2026, 7, 15, 18, 14, 0, 0, time.UTC)
	ip := "203.0.113.204"
	macs := []string{"00:00:5E:00:53:A4", "00:00:5E:00:53:B4"}

	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource},
		Segment: "lan", SensorID: sensorID, ObservedAt: at.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, len(macs))
	var wg sync.WaitGroup
	for _, mac := range macs {
		mac := mac
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := db.ObserveDevice(DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
				},
				Segment: "lan", SensorID: sensorID, ObservedAt: at,
				DeliveryEpoch: epoch, DeliverySequence: 1,
			})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	successes, conflicts := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrARPCacheDeliveryMutation):
			conflicts++
		default:
			t.Fatalf("concurrent delivery error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent first writers success/conflict=%d/%d, want 1/1", successes, conflicts)
	}

	var state, winnerHMAC string
	var sequence int64
	if err := db.QueryRow(`SELECT state, mac_hmac, delivery_sequence FROM arp_cache_states
		WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).
		Scan(&state, &winnerHMAC, &sequence); err != nil {
		t.Fatal(err)
	}
	if state != arpCacheStateUnique || len(winnerHMAC) != 64 || sequence != 1 {
		t.Fatalf("concurrent ledger state=%q hash=%q sequence=%d", state, winnerHMAC, sequence)
	}
	var canonical, fusedEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address IN (?, ?)`,
		normalizeAddress("mac", macs[0]), normalizeAddress("mac", macs[1])).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence
		WHERE evidence_type='mac' AND source=?`, arpLiveFusionSource).Scan(&fusedEvidence); err != nil {
		t.Fatal(err)
	}
	if canonical != 1 || fusedEvidence != 1 {
		t.Fatalf("concurrent generation projections canonical/evidence=%d/%d, want 1/1", canonical, fusedEvidence)
	}
}

func TestARPCacheDeliverySequenceWinsAcrossBackwardClockAndRetry(t *testing.T) {
	db := newCorrelationDB(t)
	epochA := issueTestCacheDeliveryEpoch(t, db, "sensor-sequence")
	base := time.Date(2026, 7, 15, 18, 15, 0, 0, time.UTC)
	ip := "203.0.113.201"
	macA := "00:00:5E:00:53:FB"
	macB := "00:00:5E:00:53:FC"
	observe := func(at time.Time, epoch string, sequence uint64, mac string) error {
		t.Helper()
		_, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
			},
			Segment: "lan", SensorID: "sensor-sequence", ObservedAt: at,
			DeliveryEpoch: epoch, DeliverySequence: sequence,
		})
		return err
	}

	if err := observe(base, epochA, 1, macA); err != nil {
		t.Fatal(err)
	}
	if err := observe(base.Add(-time.Minute), epochA, 2, macB); err != nil { // NTP stepped backward
		t.Fatal(err)
	}
	if err := observe(base, epochA, 1, macA); !errors.Is(err, ErrARPCacheDeliveryStale) { // delayed retry of accepted A
		t.Fatalf("delayed sequence replay error=%v, want stale", err)
	}

	var state string
	var observedAt time.Time
	var sequence, epochOrder int64
	if err := db.QueryRow(`SELECT state, observed_at, delivery_epoch_order, delivery_sequence
		FROM arp_cache_states WHERE sensor_id='sensor-sequence' AND segment='lan' AND ip_address=?`, ip).
		Scan(&state, &observedAt, &epochOrder, &sequence); err != nil {
		t.Fatal(err)
	}
	if state != arpCacheStateUnique || !observedAt.Equal(base.Add(-time.Minute)) ||
		epochOrder <= 0 || sequence != 2 {
		t.Fatalf("backward-clock ordering state=%q at=%s epoch=%d sequence=%d", state, observedAt, epochOrder, sequence)
	}

	// A restarted sensor gets a new Core-ordered epoch. Its first edge supersedes
	// the prior process even when its clock remains behind; a later retry from the
	// old epoch cannot reclaim the state.
	epochB := issueTestCacheDeliveryEpoch(t, db, "sensor-sequence")
	if err := observe(base.Add(-2*time.Minute), epochB, 1, macA); err != nil {
		t.Fatal(err)
	}
	if err := observe(base.Add(time.Minute), epochA, 3, macB); !errors.Is(err, ErrARPCacheDeliveryStale) {
		t.Fatalf("retired epoch replay error=%v, want stale", err)
	}
	var finalEpoch, finalSequence int64
	if err := db.QueryRow(`SELECT delivery_epoch_order, delivery_sequence FROM arp_cache_states
		WHERE sensor_id='sensor-sequence' AND segment='lan' AND ip_address=?`, ip).
		Scan(&finalEpoch, &finalSequence); err != nil {
		t.Fatal(err)
	}
	if finalEpoch <= epochOrder || finalSequence != 1 {
		t.Fatalf("old process reclaimed restarted epoch: before=%d final=%d/%d", epochOrder, finalEpoch, finalSequence)
	}
}

func TestARPCacheDeliveryEpochActivationIgnoresUnreceivedLateRegistration(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 17, 0, 0, time.UTC)
	sensorID := "sensor-two-phase"
	ip := "203.0.113.202"
	macA := "00:00:5E:00:53:FD"
	macB := "00:00:5E:00:53:FE"

	oldEpoch := issueTestCacheDeliveryEpoch(t, db, sensorID)
	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: macA, Status: "observed", DiscoverySource: "arp_cache"},
		Segment: "lan", SensorID: sensorID, ObservedAt: base,
		DeliveryEpoch: oldEpoch, DeliverySequence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	currentEpoch := issueTestCacheDeliveryEpoch(t, db, sensorID)
	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: macB, Status: "observed", DiscoverySource: "arp_cache"},
		Segment: "lan", SensorID: sensorID, ObservedAt: base.Add(-time.Minute),
		DeliveryEpoch: currentEpoch, DeliverySequence: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// This candidate was issued by a registration handler that completed late,
	// but its timed-out process never received it and therefore never activates it.
	_ = issueTestCacheDeliveryEpoch(t, db, sensorID)
	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: macB, Status: "observed", DiscoverySource: "arp_cache"},
		Segment: "lan", SensorID: sensorID, ObservedAt: base.Add(-2 * time.Minute),
		DeliveryEpoch: currentEpoch, DeliverySequence: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, MACAddress: macA, Status: "observed", DiscoverySource: "arp_cache"},
		Segment: "lan", SensorID: sensorID, ObservedAt: base.Add(time.Minute),
		DeliveryEpoch: oldEpoch, DeliverySequence: 2,
	}); !errors.Is(err, ErrARPCacheDeliveryStale) {
		t.Fatalf("old process replay error=%v, want stale", err)
	}

	var activeEpoch string
	if err := db.QueryRow(`SELECT delivery_epoch FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND activated_at IS NOT NULL`, sensorID).Scan(&activeEpoch); err != nil {
		t.Fatal(err)
	}
	var sequence int64
	var observedAt time.Time
	if err := db.QueryRow(`SELECT delivery_sequence, observed_at FROM arp_cache_states
		WHERE sensor_id=? AND segment='lan' AND ip_address=?`, sensorID, ip).Scan(&sequence, &observedAt); err != nil {
		t.Fatal(err)
	}
	if activeEpoch != currentEpoch || sequence != 2 || !observedAt.Equal(base.Add(-2*time.Minute)) {
		t.Fatalf("inactive late candidate displaced live process: active=%q seq=%d at=%s", activeEpoch, sequence, observedAt)
	}
}

func TestARPCacheEpochHistoryBackfillPreservesRetiredRowsFromEarlySchema(t *testing.T) {
	db := newCorrelationDB(t)
	sensorID := "sensor-epoch-backfill"
	issued := time.Date(2026, 7, 15, 18, 19, 0, 0, time.UTC)
	if _, err := db.Exec(`INSERT INTO arp_cache_delivery_epochs
		(sensor_id, delivery_epoch, issued_at, activated_at, ever_activated_at)
		VALUES (?, 'retired-early-epoch', ?, NULL, NULL),
		       (?, 'active-early-epoch', ?, ?, NULL)`,
		sensorID, issued, sensorID, issued.Add(time.Minute), issued.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.ensureAssetCenteredSchema(); err != nil {
		t.Fatalf("ensure early epoch schema: %v", err)
	}
	var retained int
	if err := db.QueryRow(`SELECT COUNT(*) FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND ever_activated_at IS NOT NULL`, sensorID).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 2 {
		t.Fatalf("activation-history backfill retained %d rows, want 2", retained)
	}
	for i := 0; i < 12; i++ {
		_ = issueTestCacheDeliveryEpoch(t, db, sensorID)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM arp_cache_delivery_epochs
		WHERE sensor_id=? AND delivery_epoch='retired-early-epoch'`, sensorID).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 1 {
		t.Fatal("backfilled retired epoch was pruned as an unreceived candidate")
	}
}

func TestCacheIdentityValidationFailsClosed(t *testing.T) {
	invalidMACs := []string{
		"not-a-mac", "00:00:5E:00:53:01:02:03", "01:00:5E:00:00:01",
		"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF",
	}
	for _, invalid := range invalidMACs {
		t.Run(strings.ReplaceAll(invalid, ":", "-"), func(t *testing.T) {
			db := newCorrelationDB(t)
			epoch := issueTestCacheDeliveryEpoch(t, db, "sensor-validation")
			if _, err := db.ObserveDevice(DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: "192.0.2.210", MACAddress: invalid,
					Status: "observed", DiscoverySource: "arp_cache",
				},
				Segment: "lan", SensorID: "sensor-validation", ObservedAt: time.Now().UTC(),
				DeliveryEpoch: epoch, DeliverySequence: 1,
			}); err != nil {
				t.Fatal(err)
			}
			var state, macHMAC string
			if err := db.QueryRow(`SELECT state, mac_hmac FROM arp_cache_states
				WHERE sensor_id='sensor-validation' AND segment='lan' AND ip_address='192.0.2.210'`).
				Scan(&state, &macHMAC); err != nil {
				t.Fatal(err)
			}
			var macRows int
			if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_history WHERE address_type='mac'`).Scan(&macRows); err != nil {
				t.Fatal(err)
			}
			if state != arpCacheStateAmbiguous || macHMAC != "" || macRows != 0 {
				t.Fatalf("invalid MAC %q persisted as identity: state=%q hash=%q rows=%d", invalid, state, macHMAC, macRows)
			}
		})
	}

	for _, invalidIP := range []string{"not-an-ip", "2001:db8::1", "127.0.0.1", "224.0.0.1", "0.0.0.0"} {
		t.Run("ip-"+strings.ReplaceAll(invalidIP, ":", "-"), func(t *testing.T) {
			db := newCorrelationDB(t)
			epoch := issueTestCacheDeliveryEpoch(t, db, "sensor-validation")
			_, err := db.ObserveDevice(DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: invalidIP, MACAddress: "02:00:5E:00:53:01",
					Status: "observed", DiscoverySource: "arp_cache",
				},
				Segment: "lan", SensorID: "sensor-validation", ObservedAt: time.Now().UTC(),
				DeliveryEpoch: epoch, DeliverySequence: 1,
			})
			if err == nil || !strings.Contains(err.Error(), "valid unicast IPv4 address") {
				t.Fatalf("invalid cache IP %q error=%v, want IPv4 validation error", invalidIP, err)
			}
		})
	}

	db := newCorrelationDB(t)
	if _, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "192.0.2.211", MACAddress: "01:00:5E:00:00:01",
			Status: "up", DiscoverySource: arpLiveFusionSource,
		},
		Segment: "lan", SensorID: "sensor-validation", ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	var mac, method string
	if err := db.QueryRow(`SELECT mac_address, discovery_method FROM devices WHERE ip_address='192.0.2.211'`).
		Scan(&mac, &method); err != nil {
		t.Fatal(err)
	}
	if mac != "" || method != nativeICMPBoundSource {
		t.Fatalf("malformed direct fused pair was trusted: mac=%q method=%q", mac, method)
	}
}

func TestUnsequencedARPCacheCannotFuseAcrossSeparateObservations(t *testing.T) {
	for _, order := range []string{"active-first", "cache-first"} {
		t.Run(order, func(t *testing.T) {
			db := newCorrelationDB(t)
			base := time.Date(2026, 7, 15, 18, 18, 0, 0, time.UTC)
			active := DeviceObservation{
				Host:    discovery.DiscoveredHost{IPAddress: "192.0.2.212", Status: "up", DiscoverySource: nativeICMPBoundSource},
				Segment: "lan", SensorID: "legacy-sensor", ObservedAt: base,
			}
			cache := DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: "192.0.2.212", MACAddress: "02:00:5E:00:53:12",
					Status: "observed", DiscoverySource: "arp_cache",
				},
				Segment: "lan", SensorID: "legacy-sensor", ObservedAt: base.Add(time.Minute),
			}
			if order == "active-first" {
				if _, err := db.ObserveDevice(active); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ObserveDevice(cache); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := db.ObserveDevice(cache); err != nil {
					t.Fatal(err)
				}
				active.ObservedAt = base.Add(time.Minute)
				if _, err := db.ObserveDevice(active); err != nil {
					t.Fatal(err)
				}
			}
			var fused int
			if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE discovery_method=?`, arpLiveFusionSource).Scan(&fused); err != nil {
				t.Fatal(err)
			}
			if fused != 0 {
				t.Fatalf("unsequenced legacy cache fused in %s order", order)
			}
		})
	}
}

func TestExpectedARPCacheFusionRejectsNewerAmbiguousTransition(t *testing.T) {
	db := newCorrelationDB(t)
	epoch := issueTestCacheDeliveryEpoch(t, db, "sensor-a")
	base := time.Date(2026, 7, 15, 18, 20, 0, 0, time.UTC)
	ip := "203.0.113.200"
	mac := "00:00:5E:00:53:FA"
	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, Status: "up", DiscoverySource: nativeICMPBoundSource},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
	}); err != nil {
		t.Fatal(err)
	}

	// Model the committed first half of the active-first path and retain the
	// exact state it expected to authorize fusion in the second transaction.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE settings SET value=value WHERE key=?`, identityHMACSetting); err != nil {
		t.Fatal(err)
	}
	uniqueAt := base.Add(time.Minute)
	if err := db.recordARPCacheStateTx(tx, ip, mac, "lan", "sensor-a", uniqueAt,
		epoch, 1); err != nil {
		t.Fatal(err)
	}
	state, err := db.scopedARPCacheStateTx(tx, ip, "lan", "sensor-a")
	if err != nil {
		t.Fatal(err)
	}
	expected := &arpCacheExpectation{
		sensorID: "sensor-a", segment: "lan", ipAddress: ip,
		macHMAC: state.macHMAC, observedAt: uniqueAt, epochOrder: state.epochOrder,
		deliverySequence: state.deliverySequence,
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// A newer blank/proxy transition wins while the two active-first
	// transactions are separated. The stale expected-A continuation must become
	// a no-op instead of persisting A as canonical identity evidence.
	if _, err := db.ObserveDevice(DeviceObservation{
		Host:    discovery.DiscoveredHost{IPAddress: ip, Status: "observed", DiscoverySource: "arp_cache"},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(2 * time.Minute),
		DeliveryEpoch: epoch, DeliverySequence: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "up", DiscoverySource: arpLiveFusionSource,
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: uniqueAt,
		expectedARPCache: expected,
	}); err != nil {
		t.Fatal(err)
	}

	var canonical, evidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address=?`, normalizeAddress("mac", mac)).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source=?`, arpLiveFusionSource).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if canonical != 0 || evidence != 0 {
		t.Fatalf("stale expected cache state fused after ambiguity: canonical=%d evidence=%d", canonical, evidence)
	}
}

func TestObserveDevicePlainNativeICMPCannotFuseWithARPCache(t *testing.T) {
	for _, order := range []string{"active-first", "cache-first"} {
		t.Run(order, func(t *testing.T) {
			db := newCorrelationDB(t)
			base := time.Date(2026, 7, 15, 17, 45, 0, 0, time.UTC)
			ip := "203.0.113.98"
			mac := "00:00:5E:00:53:98"
			active := DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: ip, Status: "up", DiscoverySource: "native_icmp",
				},
				Segment: "lan", SensorID: "windows-sensor",
			}
			cache := DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
				},
				Segment: "lan", SensorID: "windows-sensor",
			}
			if order == "active-first" {
				active.ObservedAt = base
				cache.ObservedAt = base.Add(time.Minute)
				if _, err := db.ObserveDevice(active); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ObserveDevice(cache); err != nil {
					t.Fatal(err)
				}
			} else {
				cache.ObservedAt = base
				active.ObservedAt = base.Add(time.Minute)
				if _, err := db.ObserveDevice(cache); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ObserveDevice(active); err != nil {
					t.Fatal(err)
				}
			}

			var canonicalMACs, fusedEvidence int
			if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE COALESCE(mac_address, '') != ''`).Scan(&canonicalMACs); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence WHERE source = ?`, arpLiveFusionSource).Scan(&fusedEvidence); err != nil {
				t.Fatal(err)
			}
			if canonicalMACs != 0 || fusedEvidence != 0 {
				t.Fatalf("unbound native ICMP fused with link cache: canonical=%d fused_evidence=%d", canonicalMACs, fusedEvidence)
			}
		})
	}
}

func TestObserveDeviceNativeLivenessSourcesCannotCarryMACOrIdentityClaims(t *testing.T) {
	for _, source := range []string{"native_icmp", nativeICMPBoundSource} {
		t.Run(source, func(t *testing.T) {
			db := newCorrelationDB(t)
			created, err := db.ObserveDevice(DeviceObservation{
				Host: discovery.DiscoveredHost{
					IPAddress: "192.0.2.199", MACAddress: "00:00:5E:00:53:C7",
					Hostname: "spliced-host", Vendor: "spliced-vendor", Model: "spliced-model",
					FriendlyName: "spliced-friendly", OpenPorts: []int{23}, Services: []string{"_spliced._tcp"},
					DiscoverySource: source,
					IdentityEvidence: []discovery.IdentityEvidence{{
						Type: "dhcp_client_id", Value: "spliced-client-id", Source: "passive_dhcp", Confidence: 1,
					}},
				},
				Segment: "lan", SensorID: "windows-sensor", ObservedAt: time.Now().UTC(),
				Evidence: []DeviceIdentityEvidenceInput{{
					Type: "ssdp_uuid", Value: "spliced-uuid", Source: "passive_ssdp", Confidence: 1,
				}},
			})
			if err != nil || !created {
				t.Fatalf("native observation: created=%v err=%v", created, err)
			}
			var mac, hostname, vendor, model, friendly, ports, services, method string
			if err := db.QueryRow(`SELECT mac_address, hostname, vendor, model, friendly_name,
				open_ports, services, discovery_method FROM devices`).Scan(
				&mac, &hostname, &vendor, &model, &friendly, &ports, &services, &method); err != nil {
				t.Fatal(err)
			}
			if mac != "" || hostname != "" || vendor != "" || model != "" || friendly != "" ||
				ports != "[]" || services != "[]" || method != source {
				t.Fatalf("%s escaped IP-only boundary: mac=%q host=%q vendor=%q model=%q friendly=%q ports=%s services=%s method=%q",
					source, mac, hostname, vendor, model, friendly, ports, services, method)
			}
			var evidenceCount int
			if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence`).Scan(&evidenceCount); err != nil {
				t.Fatal(err)
			}
			if evidenceCount != 0 {
				t.Fatalf("%s persisted %d identity claims, want none", source, evidenceCount)
			}
		})
	}
}

func TestObserveDeviceNativeICMPARPAllowsOnlyScopedNetworkPair(t *testing.T) {
	db := newCorrelationDB(t)
	mac := "00:00:5E:00:53:C8"
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "192.0.2.200", MACAddress: mac,
			Hostname: "spliced-host", Vendor: "spliced-vendor", Model: "spliced-model",
			FriendlyName: "spliced-friendly", OpenPorts: []int{23}, Services: []string{"_spliced._tcp"},
			DiscoverySource: arpLiveFusionSource,
			IdentityEvidence: []discovery.IdentityEvidence{{
				Type: "dhcp_client_id", Value: "spliced-client-id", Source: "passive_dhcp", Confidence: 1,
			}},
		},
		Segment: "lan", SensorID: "windows-sensor", ObservedAt: time.Now().UTC(),
		Evidence: []DeviceIdentityEvidenceInput{{
			Type: "ssdp_uuid", Value: "spliced-uuid", Source: "passive_ssdp", Confidence: 1,
		}},
	})
	if err != nil || !created {
		t.Fatalf("joined native observation: created=%v err=%v", created, err)
	}
	var gotMAC, hostname, vendor, model, friendly, ports, services, method string
	if err := db.QueryRow(`SELECT mac_address, hostname, vendor, model, friendly_name,
		open_ports, services, discovery_method FROM devices`).Scan(
		&gotMAC, &hostname, &vendor, &model, &friendly, &ports, &services, &method); err != nil {
		t.Fatal(err)
	}
	// A vendor derived locally from the allowed MAC/OUI is safe. The supplied
	// descriptive vendor remains untrusted and must not cross this source boundary.
	if normalizeAddress("mac", gotMAC) != normalizeAddress("mac", mac) || hostname != "" || vendor == "spliced-vendor" ||
		model != "" || friendly != "" || ports != "[]" || services != "[]" || method != arpLiveFusionSource {
		t.Fatalf("joined source boundary = mac=%q host=%q vendor=%q model=%q friendly=%q ports=%s services=%s method=%q",
			gotMAC, hostname, vendor, model, friendly, ports, services, method)
	}
	var evidenceSource string
	var confidence float64
	var evidenceCount, unexpectedEvidence int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence`).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT source, confidence FROM device_identity_evidence WHERE evidence_type='mac'`).
		Scan(&evidenceSource, &confidence); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence
		WHERE evidence_type NOT IN ('mac', 'oui')`).Scan(&unexpectedEvidence); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 2 || unexpectedEvidence != 0 || evidenceSource != arpLiveFusionSource || confidence != arpLiveFusionConfidence {
		t.Fatalf("joined identity evidence count=%d unexpected=%d source=%q confidence=%.2f",
			evidenceCount, unexpectedEvidence, evidenceSource, confidence)
	}
}

func TestObserveDeviceStrongMACDoesNotPromoteDifferentCacheProvisionalAfterStaleOwner(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)
	oldIP := "198.51.100.96"
	newIP := "198.51.100.97"
	macA := "00:00:5E:00:53:A6"
	macB := "00:00:5E:00:53:B6"

	ownerID := observeAsset(t, db, base, "sensor-a", "lan", oldIP, macA, "first-owner")
	if moved := observeAsset(t, db, base.Add(time.Minute), "sensor-a", "lan", newIP, macA, "first-owner"); moved != ownerID {
		t.Fatalf("moving stale owner split identity: got %q want %q", moved, ownerID)
	}
	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: oldIP, MACAddress: macA, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(2 * time.Minute),
	})
	if err != nil || !created {
		t.Fatalf("stale cache provisional: created=%v err=%v", created, err)
	}
	var provisionalID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE discovery_method='arp_cache' AND ip_address=?`, oldIP).
		Scan(&provisionalID); err != nil {
		t.Fatal(err)
	}

	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: oldIP, MACAddress: macB, Hostname: "replacement-owner", DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(3 * time.Minute),
	})
	if err != nil || !created {
		t.Fatalf("strong replacement owner: created=%v err=%v, want a distinct device", created, err)
	}
	if got := countDevices(t, db); got != 3 {
		t.Fatalf("replacement collapsed stale owner/provisional: got %d devices, want 3", got)
	}
	var provisionalMAC, provisionalMethod string
	if err := db.QueryRow(`SELECT mac_address, discovery_method FROM devices WHERE device_id=?`, provisionalID).
		Scan(&provisionalMAC, &provisionalMethod); err != nil {
		t.Fatal(err)
	}
	if provisionalMAC != "" || provisionalMethod != "arp_cache" {
		t.Fatalf("MAC-B promoted MAC-A cache provisional: mac=%q method=%q", provisionalMAC, provisionalMethod)
	}
	var replacementID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address=?`, normalizeAddress("mac", macB)).Scan(&replacementID); err != nil {
		t.Fatal(err)
	}
	if replacementID == ownerID || replacementID == provisionalID {
		t.Fatalf("replacement identity reused stale row: replacement=%q owner=%q provisional=%q", replacementID, ownerID, provisionalID)
	}
}

func TestObserveDeviceMergedFamilyHMACOnlyMACVetoesLegacyIPFallback(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 30, 0, 0, time.UTC)
	targetIP := "192.0.2.210"
	cacheIP := "192.0.2.211"
	cacheMAC := "00:00:5E:00:53:D1"
	incomingMAC := "00:00:5E:00:53:D2"

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: targetIP, Status: "up", DiscoverySource: nativeICMPBoundSource,
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
	})
	if err != nil || !created {
		t.Fatalf("create MAC-less canonical target: created=%v err=%v", created, err)
	}
	var targetID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address=?`, targetIP).Scan(&targetID); err != nil {
		t.Fatal(err)
	}

	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: cacheIP, MACAddress: cacheMAC, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Second),
	})
	if err != nil || !created {
		t.Fatalf("create HMAC-only cache child: created=%v err=%v", created, err)
	}
	var childID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address=?`, cacheIP).Scan(&childID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MergeDevices(context.Background(), childID, targetID,
		"same synthetic device", "test-admin"); err != nil {
		t.Fatalf("merge cache evidence under canonical target: %v", err)
	}

	// The target itself has no canonical/direct MAC. The only conflict evidence is
	// the active HMAC-only cache MAC retained on its redirected child. A lookup that
	// examines only the target row will attach this contradictory MAC through the
	// legacy IP fallback and overwrite the canonical family.
	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: targetIP, MACAddress: incomingMAC, Hostname: "replacement-device",
			DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Minute),
	})
	if err != nil || !created {
		t.Fatalf("contradictory family MAC must create a distinct device: created=%v err=%v", created, err)
	}
	var targetMAC string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE device_id=?`, targetID).Scan(&targetMAC); err != nil {
		t.Fatal(err)
	}
	if targetMAC != "" {
		t.Fatalf("legacy fallback overwrote MAC-less canonical family with %q", targetMAC)
	}
	var replacementID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address=?`, incomingMAC).Scan(&replacementID); err != nil {
		t.Fatal(err)
	}
	if replacementID == targetID || replacementID == childID {
		t.Fatalf("replacement reused conflicting family: replacement=%q target=%q child=%q",
			replacementID, targetID, childID)
	}
}

func TestMacConflictsChecksMergedFamilyWhenCanonicalMACMatches(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 40, 0, 0, time.UTC)
	canonicalMAC := "00:00:5E:00:53:E1"
	childMAC := "00:00:5E:00:53:E2"

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "192.0.2.220", MACAddress: canonicalMAC,
			Hostname: "family-canonical", DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
	})
	if err != nil || !created {
		t.Fatalf("create canonical device: created=%v err=%v", created, err)
	}
	var canonicalID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address=?`, canonicalMAC).Scan(&canonicalID); err != nil {
		t.Fatal(err)
	}

	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: "192.0.2.221", MACAddress: childMAC,
			Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Second),
	})
	if err != nil || !created {
		t.Fatalf("create cache child: created=%v err=%v", created, err)
	}
	var childID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address='192.0.2.221'`).Scan(&childID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MergeDevices(context.Background(), childID, canonicalID, "same synthetic device", "test-admin"); err != nil {
		t.Fatal(err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	conflict, err := db.macConflicts(tx, canonicalID, canonicalMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !conflict {
		t.Fatal("matching canonical MAC masked contradictory active MAC evidence on merged child")
	}
}

func TestARPCacheRefreshDoesNotTouchAnotherSensorsNetworkAttachment(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC)
	observedAt := base.Add(time.Hour)
	ip := "192.0.2.230"
	mac := "00:00:5E:00:53:F0"

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Hostname: "sensor-b-device",
			DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-b", ObservedAt: base,
	})
	if err != nil || !created {
		t.Fatalf("create sensor-b device: created=%v err=%v", created, err)
	}
	var deviceID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE mac_address=?`, mac).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	// Sensor A has independent strong address history for the canonical device,
	// while the inventory's current network attachment still belongs to sensor B.
	if _, err := db.Exec(`INSERT INTO device_address_history
		(binding_id, device_id, address_type, address_value, segment, sensor_id,
		 first_seen, last_seen, valid_from, valid_until, evidence_source, confidence, created_at)
		VALUES (?, ?, 'ip', ?, 'lan', 'sensor-a', ?, ?, ?, NULL, 'passive_dhcp', 0.9, ?)`,
		"synthetic-sensor-a-binding", deviceID, ip, base, observedAt, base, base); err != nil {
		t.Fatal(err)
	}
	epoch := issueTestCacheDeliveryEpoch(t, db, "sensor-a")
	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: observedAt,
		DeliveryEpoch: epoch, DeliverySequence: 1,
	})
	if err != nil || created {
		t.Fatalf("corroborating cache observation: created=%v err=%v", created, err)
	}
	var networkSensor string
	var networkLastSeen time.Time
	if err := db.QueryRow(`SELECT sensor_id, last_seen FROM device_networks WHERE device_id=? AND segment='lan'`, deviceID).
		Scan(&networkSensor, &networkLastSeen); err != nil {
		t.Fatal(err)
	}
	if networkSensor != "sensor-b" || !networkLastSeen.Equal(base) {
		t.Fatalf("sensor-a refreshed sensor-b attachment: sensor=%q last_seen=%s, want sensor-b/%s",
			networkSensor, networkLastSeen, base)
	}
}

func assertNativeARPFusion(t *testing.T, db *DB, wantID, wantMAC string) {
	t.Helper()
	if got := countDevices(t, db); got != 1 {
		t.Fatalf("native ICMP + ARP created %d devices, want 1", got)
	}
	var deviceID, mac, method, display string
	if err := db.QueryRow(`SELECT device_id, mac_address, discovery_method, display_name FROM devices`).
		Scan(&deviceID, &mac, &method, &display); err != nil {
		t.Fatal(err)
	}
	if deviceID != wantID || normalizeAddress("mac", mac) != normalizeAddress("mac", wantMAC) ||
		method != arpLiveFusionSource || display == "" {
		t.Fatalf("native ICMP + ARP fusion = id=%q mac=%q method=%q display=%q",
			deviceID, mac, method, display)
	}
	var source string
	var confidence float64
	if err := db.QueryRow(`SELECT source, confidence FROM device_identity_evidence
		WHERE device_id=? AND evidence_type='mac'`, deviceID).Scan(&source, &confidence); err != nil {
		t.Fatal(err)
	}
	if source != arpLiveFusionSource || confidence != arpLiveFusionConfidence {
		t.Fatalf("fused MAC evidence = source=%q confidence=%v", source, confidence)
	}
}

func TestObserveDeviceStableDHCPIdentitySurvivesAddressAndMACChange(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	clientID := evidence("dhcp_client_id", "01:synthetic-client-53", 0.95)

	firstID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.10", "00:00:5E:00:53:10", "workstation-53", clientID)
	secondID := observeAsset(t, db, base.Add(time.Hour), "sensor-a", "lan", "192.0.2.11", "00:00:5E:00:53:11", "workstation-53", clientID)
	if firstID != secondID {
		t.Fatalf("stable DHCP client ID split one asset: %s != %s", firstID, secondID)
	}
	if got, err := db.CountDevices(); err != nil || got != 1 {
		t.Fatalf("active devices = %d err=%v, want 1", got, err)
	}
}

func TestObserveDeviceOutOfOrderHistoryDoesNotRegressCurrentProjection(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	mac := "00:00:5E:00:53:12"

	observeAsset(t, db, base.Add(2*time.Hour), "sensor-a", "lan", "192.0.2.12", mac, "newer-name")
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.11", mac, "older-name")

	var firstSeen, lastSeen time.Time
	var currentIP, hostname string
	if err := db.QueryRow(`SELECT first_seen, last_seen, ip_address, hostname FROM devices WHERE device_id = ?`, deviceID).
		Scan(&firstSeen, &lastSeen, &currentIP, &hostname); err != nil {
		t.Fatal(err)
	}
	if !firstSeen.Equal(base) || !lastSeen.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("device bounds regressed: first=%s last=%s", firstSeen, lastSeen)
	}
	if currentIP != "192.0.2.12" || hostname != "newer-name" {
		t.Fatalf("current projection regressed to delayed observation: ip=%q hostname=%q", currentIP, hostname)
	}
	var networkIP string
	if err := db.QueryRow(`SELECT ip_address FROM device_networks WHERE device_id = ? AND segment = 'lan'`, deviceID).Scan(&networkIP); err != nil {
		t.Fatal(err)
	}
	if networkIP != "192.0.2.12" {
		t.Fatalf("network projection regressed: %q", networkIP)
	}
}

func TestObserveDeviceOutOfOrderStableIdentityDoesNotRegressCurrentMAC(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	clientID := evidence("dhcp_client_id", "stable-randomized-client", 0.95)
	oldMAC := "02:00:5E:00:53:13"
	currentMAC := "02:00:5E:00:53:14"

	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.13", oldMAC, "phone-13", clientID)
	if got := observeAsset(t, db, base.Add(2*time.Hour), "sensor-a", "lan", "192.0.2.14", currentMAC, "phone-13", clientID); got != deviceID {
		t.Fatalf("stable identity split after MAC rotation: %s != %s", got, deviceID)
	}
	// This delayed observation must extend history without replacing the newest
	// compatibility projection on devices.mac_address.
	if got := observeAsset(t, db, base.Add(time.Hour), "sensor-a", "lan", "192.0.2.13", oldMAC, "phone-13", clientID); got != deviceID {
		t.Fatalf("delayed stable identity split: %s != %s", got, deviceID)
	}

	var mac string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE device_id = ?`, deviceID).Scan(&mac); err != nil {
		t.Fatal(err)
	}
	if mac != currentMAC {
		t.Fatalf("current MAC regressed to delayed observation: got %q want %q", mac, currentMAC)
	}
}

func TestResolveDeviceAtUsesTimestampAndDoesNotAttachReusedIP(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	ip := "192.0.2.20"
	firstID := observeAsset(t, db, base, "sensor-a", "lan", ip, "00:00:5E:00:53:20", "camera-a")
	secondAt := base.Add(2 * time.Hour)
	secondID := observeAsset(t, db, secondAt, "sensor-a", "lan", ip, "00:00:5E:00:53:21", "camera-b")
	if firstID == secondID {
		t.Fatal("reused IP with a conflicting MAC collapsed two assets")
	}

	before, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(time.Hour), IPAddress: ip, Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil || before.DeviceID != firstID {
		t.Fatalf("historical resolve = %+v err=%v, want %s", before, err, firstID)
	}
	after, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: secondAt.Add(time.Minute), IPAddress: ip, Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil || after.DeviceID != secondID {
		t.Fatalf("post-reuse resolve = %+v err=%v, want %s", after, err, secondID)
	}
}

func TestDelayedConflictingOwnerPreservesLaterExplicitOwner(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	ip := "192.0.2.23"
	ownerA := observeAsset(t, db, base, "sensor-a", "lan", ip, "00:00:5E:00:53:23", "camera-a")
	if repeated := observeAsset(t, db, base.Add(2*time.Hour), "sensor-a", "lan", ip, "00:00:5E:00:53:23", "camera-a"); repeated != ownerA {
		t.Fatalf("repeat observation changed owner: %s != %s", repeated, ownerA)
	}
	ownerB := observeAsset(t, db, base.Add(time.Hour), "sensor-a", "lan", ip, "00:00:5E:00:53:24", "camera-b")
	if ownerA == ownerB {
		t.Fatal("delayed conflicting MAC collapsed two assets")
	}

	duringB, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(90 * time.Minute), IPAddress: ip, Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil || duringB.DeviceID != ownerB {
		t.Fatalf("delayed-owner interval = %+v err=%v, want %s", duringB, err, ownerB)
	}
	afterAReappeared, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(2*time.Hour + time.Minute), IPAddress: ip, Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil || afterAReappeared.DeviceID != ownerA {
		t.Fatalf("later explicit owner was erased: %+v err=%v, want %s", afterAReappeared, err, ownerA)
	}
}

func TestResolveDeviceAtDoesNotUseStaleOpenAddressBinding(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.22", "00:00:5E:00:53:22", "camera-22")
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(48 * time.Hour), IPAddress: "192.0.2.22", Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil || got.DeviceID != "" || got.Reason != "unresolved" {
		t.Fatalf("stale address binding resolved: %+v err=%v", got, err)
	}
}

func TestResolveDeviceAtDoesNotTreatClosedAddressIntervalAsContinuousObservation(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	ip := "192.0.2.24"
	ownerA := observeAsset(t, db, base, "sensor-a", "lan", ip, "00:00:5E:00:53:24", "camera-a")
	reusedAt := base.Add(72 * time.Hour)
	ownerB := observeAsset(t, db, reusedAt, "sensor-a", "lan", ip, "00:00:5E:00:53:25", "camera-b")
	if ownerA == ownerB {
		t.Fatal("reused IP with a conflicting MAC collapsed two assets")
	}

	// Closure bounds ownership but does not prove the address was observed
	// continuously. The explicit freshness window has a gap at 48 hours.
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(48 * time.Hour), IPAddress: ip, Segment: "lan", SensorID: "sensor-a",
	})
	if err != nil || got.DeviceID != "" || got.Reason != "unresolved" {
		t.Fatalf("stale closed interval filled an observation gap: %+v err=%v", got, err)
	}
}

func TestResolveDeviceAtDelayedEventUsesClosedIntervalAcrossUnknownScope(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	ip := "198.51.100.24"
	ownerA := observeAsset(t, db, base, "sensor-a", "iot", ip, "00:00:5E:00:53:26", "camera-a")
	for _, delta := range []time.Duration{20 * time.Hour, 40 * time.Hour, 60 * time.Hour} {
		if got := observeAsset(t, db, base.Add(delta), "sensor-a", "iot", ip,
			"00:00:5E:00:53:26", "camera-a"); got != ownerA {
			t.Fatalf("continuous owner observation at %s changed identity: %s", delta, got)
		}
	}
	reusedAt := base.Add(72 * time.Hour)
	ownerB := observeAsset(t, db, reusedAt, "sensor-a", "iot", ip, "00:00:5E:00:53:27", "camera-b")
	if ownerA == ownerB {
		t.Fatal("reused IP with a conflicting MAC collapsed two assets")
	}

	// Sources without segment/sensor context take the global uniqueness path. The
	// delayed event is supported by overlapping 24-hour observation windows, so
	// later ownership closure cannot erase that positive historical evidence.
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(48 * time.Hour), IPAddress: ip, Segment: "default",
	})
	if err != nil || got.DeviceID != ownerA || got.Reason != "unique_unscoped_address_binding" {
		t.Fatalf("delayed unscoped resolution = %+v err=%v, want owner A %s", got, err, ownerA)
	}
	if got.Confidence > 0.60 {
		t.Fatalf("unscoped historical resolution confidence = %.2f, want <= 0.60", got.Confidence)
	}
}

func TestResolveDeviceAtConflictingStrongEvidenceIsUnresolved(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.30", "00:00:5E:00:53:30", "host-a",
		evidence("dhcp_client_id", "client-a", 0.95))
	observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.31", "00:00:5E:00:53:31", "host-b",
		evidence("dhcp_client_id", "client-b", 0.95))

	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(time.Minute), Segment: "lan", SensorID: "sensor-a",
		Evidence: []DeviceIdentityEvidenceInput{
			{Type: "dhcp_client_id", Value: "client-a", Confidence: 0.95},
			{Type: "dhcp_client_id", Value: "client-b", Confidence: 0.95},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "" || got.Reason != "conflicting_identity_evidence" {
		t.Fatalf("conflicting evidence resolved unsafely: %+v", got)
	}
}

func TestResolveDeviceAtCrossRankStableIDAndDifferentKnownMACConflicts(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	clientA := evidence("dhcp_client_id", "client-a-cross-rank", 0.95)
	observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.32", "00:00:5E:00:53:32", "host-a", clientA)
	observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.33", "00:00:5E:00:53:33", "host-b")

	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(time.Minute), Segment: "lan", SensorID: "sensor-a",
		MACAddress: "00:00:5E:00:53:33",
		Evidence:   []DeviceIdentityEvidenceInput{{Type: "dhcp_client_id", Value: "client-a-cross-rank", Confidence: 0.95}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "" || got.Reason != "conflicting_identity_evidence" {
		t.Fatalf("cross-rank contradiction resolved unsafely: %+v", got)
	}
}

func TestWeakOperatorConfirmationCannotCollapseDifferentMAC(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	firstID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.34", "00:00:5E:00:53:34", "shared-printer")
	if _, err := db.ConfirmDeviceIdentity(context.Background(), firstID,
		DeviceIdentityEvidenceInput{Type: "hostname", Value: "shared-printer"},
		"lan", "sensor-a", "tester", "physically verified", base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	secondID := observeAsset(t, db, base.Add(2*time.Minute), "sensor-a", "lan", "192.0.2.35", "00:00:5E:00:53:35", "shared-printer")
	if firstID == secondID {
		t.Fatal("weak confirmation collapsed a second physical device")
	}
	var firstMAC string
	if err := db.QueryRow(`SELECT mac_address FROM devices WHERE device_id = ?`, firstID).Scan(&firstMAC); err != nil {
		t.Fatal(err)
	}
	if firstMAC != "00:00:5E:00:53:34" {
		t.Fatalf("confirmed device MAC was overwritten: %q", firstMAC)
	}
}

func TestResolveDeviceAtDefaultSegmentUsesOnlyUniqueCrossSegmentAddress(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	id := observeAsset(t, db, base, "sensor-a", "iot", "192.0.2.36", "00:00:5E:00:53:36", "camera-36")
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(time.Minute), IPAddress: "192.0.2.36", Segment: "default",
	})
	if err != nil || got.DeviceID != id || got.Reason != "unique_unscoped_address_binding" || got.Confidence > 0.60 {
		t.Fatalf("unique unscoped resolution = %+v err=%v", got, err)
	}

	observeAsset(t, db, base, "sensor-b", "guest", "198.51.100.36", "00:00:5E:00:53:37", "guest-36")
	observeAsset(t, db, base, "sensor-c", "iot", "198.51.100.36", "00:00:5E:00:53:38", "iot-36")
	ambiguous, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(time.Minute), IPAddress: "198.51.100.36", Segment: "default",
	})
	if err != nil || ambiguous.DeviceID != "" || ambiguous.Reason != "ambiguous_temporal_address" {
		t.Fatalf("overlapping cross-segment address resolved: %+v err=%v", ambiguous, err)
	}
}

func TestAliasAndFingerprintEvidenceIsSegmentScopedAndCorroborated(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	shared := []discovery.IdentityEvidence{
		evidence("hostname", "shared-camera", 0.65),
		evidence("dhcp_option_55", "1,3,6,15,119", 0.55),
	}
	lanID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.40", "02:00:5E:00:53:40", "shared-camera", shared...)
	iotID := observeAsset(t, db, base, "sensor-a", "iot", "198.51.100.40", "02:00:5E:00:53:40", "shared-camera", shared...)
	if lanID == iotID {
		t.Fatal("locally administered MAC/alias evidence crossed segment scope")
	}

	resolve := func(segment string) DeviceIdentityResolution {
		got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
			Timestamp: base.Add(time.Minute), Segment: segment, SensorID: "sensor-a",
			Evidence: []DeviceIdentityEvidenceInput{
				{Type: "hostname", Value: "shared-camera"},
				{Type: "dhcp_option_55", Value: "1,3,6,15,119"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := resolve("lan"); got.DeviceID != lanID {
		t.Fatalf("LAN scoped resolution = %+v, want %s", got, lanID)
	}
	if got := resolve("iot"); got.DeviceID != iotID {
		t.Fatalf("IoT scoped resolution = %+v, want %s", got, iotID)
	}

	// One common fingerprint without corroboration is never an identity.
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(time.Minute), Segment: "lan", SensorID: "sensor-a",
		Evidence: []DeviceIdentityEvidenceInput{{Type: "dhcp_option_55", Value: "1,3,6,15,119"}},
	})
	if err != nil || got.DeviceID != "" {
		t.Fatalf("uncorroborated fingerprint resolved: %+v err=%v", got, err)
	}
}

func TestResolveDeviceAtDoesNotTreatClosedAliasIntervalAsContinuousObservation(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.41", "02:00:5E:00:53:41", "quiet-camera",
		evidence("dhcp_option_55", "1,3,6,15,119", 0.55))
	closedAt := base.Add(30 * 24 * time.Hour)
	if _, err := db.Exec(`UPDATE device_identity_evidence SET valid_until = ?
		WHERE device_id = ? AND evidence_type IN ('hostname', 'dhcp_option_55')`, closedAt, deviceID); err != nil {
		t.Fatal(err)
	}

	// Closing an alias interval does not manufacture observations during its
	// seven-day freshness gap.
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(14 * 24 * time.Hour), Segment: "lan", SensorID: "sensor-a",
		Evidence: []DeviceIdentityEvidenceInput{
			{Type: "hostname", Value: "quiet-camera"},
			{Type: "dhcp_option_55", Value: "1,3,6,15,119"},
		},
	})
	if err != nil || got.DeviceID != "" || got.Reason != "unresolved" {
		t.Fatalf("stale closed alias filled an observation gap: %+v err=%v", got, err)
	}
}

func TestResolveDeviceAtDoesNotUseStaleOpenAliasEvidence(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.42", "02:00:5E:00:53:42", "quiet-open-camera",
		evidence("dhcp_option_55", "1,3,6,15,119", 0.55))

	// Without a fresh observation window, the normal seven-day recency limit
	// applies regardless of whether the parent row is currently open or closed.
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(14 * 24 * time.Hour), Segment: "lan", SensorID: "sensor-a",
		Evidence: []DeviceIdentityEvidenceInput{
			{Type: "hostname", Value: "quiet-open-camera"},
			{Type: "dhcp_option_55", Value: "1,3,6,15,119"},
		},
	})
	if err != nil || got.DeviceID != "" {
		t.Fatalf("stale open alias resolved: %+v err=%v", got, err)
	}
}

func TestSensitiveIdentityEvidenceIsHMACOnly(t *testing.T) {
	db := newCorrelationDB(t)
	raw := "synthetic-private-client-id-53"
	observeAsset(t, db, time.Now().UTC(), "sensor-a", "lan", "192.0.2.53", "00:00:5E:00:53:53", "camera-53",
		evidence("dhcp_client_id", raw, 0.95))
	var valueHash, display string
	if err := db.QueryRow(`SELECT value_hmac, value_display FROM device_identity_evidence
		WHERE evidence_type='dhcp_client_id'`).Scan(&valueHash, &display); err != nil {
		t.Fatal(err)
	}
	if valueHash == raw || len(valueHash) != 64 || display != "" {
		t.Fatalf("sensitive evidence persisted unsafely: hash=%q display=%q", valueHash, display)
	}
	var leaked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence
		WHERE value_hmac = ? OR value_display = ? OR metadata LIKE ?`, raw, raw, "%"+raw+"%").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("raw sensitive identifier found in persisted identity evidence")
	}
}

func TestSourceHashIsStableCoreOwnedHMAC(t *testing.T) {
	db := newCorrelationDB(t)
	one, err := db.SourceHash(context.Background(), "192.0.2.44")
	if err != nil {
		t.Fatalf("first source hash: %v", err)
	}
	again, err := db.SourceHash(context.Background(), "192.0.2.44")
	if err != nil {
		t.Fatalf("repeat source hash: %v", err)
	}
	other, err := db.SourceHash(context.Background(), "192.0.2.45")
	if err != nil {
		t.Fatalf("other source hash: %v", err)
	}
	if len(one) != 64 || one != again || one == other || strings.Contains(one, "192.0.2.44") {
		t.Fatalf("unexpected local source pseudonyms: one=%q again=%q other=%q", one, again, other)
	}
}

func TestOperatorConfirmationIsAuditedAndWinsResolution(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.52", "00:00:5E:00:53:52", "host-52")
	action, err := db.ConfirmDeviceIdentity(context.Background(), deviceID,
		DeviceIdentityEvidenceInput{Type: "hostname", Value: "confirmed-host-52", Metadata: map[string]any{"raw": "must-not-persist"}},
		"lan", "sensor-a", "test-admin", "operator verified the label", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if action.ActionType != "confirm" || action.EvidenceID == "" {
		t.Fatalf("confirmation action = %+v", action)
	}
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: base.Add(2 * time.Minute), Segment: "lan", SensorID: "sensor-a",
		Evidence: []DeviceIdentityEvidenceInput{{Type: "hostname", Value: "confirmed-host-52"}},
	})
	if err != nil || got.DeviceID != deviceID || got.Reason != "operator_confirmed_identity" || got.Confidence != 1 {
		t.Fatalf("operator confirmation did not win: %+v err=%v", got, err)
	}
	var metadata string
	if err := db.QueryRow(`SELECT metadata FROM device_identity_evidence WHERE evidence_id=?`, action.EvidenceID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadata != "{}" {
		t.Fatalf("arbitrary identity metadata persisted: %s", metadata)
	}
}

func TestResolveDeviceAtFreshDBInitializesKeyAndReturnsUnresolved(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{Timestamp: time.Now().UTC()})
	if err != nil || got.DeviceID != "" || got.Reason != "unresolved" {
		t.Fatalf("fresh resolution = %+v err=%v", got, err)
	}
	var encoded string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, identityHMACSetting).Scan(&encoded); err != nil || len(encoded) != 64 {
		t.Fatalf("identity HMAC key was not initialized: len=%d err=%v", len(encoded), err)
	}
}

func TestLegacyEventStorePersistsAdditiveIdentityFields(t *testing.T) {
	db := newCorrelationDB(t)
	deviceID := observeAsset(t, db, time.Now().UTC(), "sensor-a", "lan", "192.0.2.54", "00:00:5E:00:53:54", "host-54")
	event := models.Event{
		EventID: "event-identity-54", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "local-source-hash",
		DeviceID: deviceID, IdentityConfidence: 0.75, IdentityReason: "temporal_address_binding",
		IdentityEvidence: `{"reason":"temporal_address_binding"}`, Origin: "sensor_dns", SensorID: "sensor-a",
		Disposition: "suppressed", SuppressionRuleID: "synthetic-rule-54",
	}
	if n, err := db.InsertEvents([]models.Event{event}); err != nil || n != 1 {
		t.Fatalf("insert additive event fields: n=%d err=%v", n, err)
	}
	result, err := db.QueryEvents(EventQueryParams{DeviceID: deviceID, Origin: "sensor_dns"})
	if err != nil || len(result.Events) != 1 {
		t.Fatalf("query identity fields: result=%+v err=%v", result, err)
	}
	got := result.Events[0]
	if got.DeviceID != deviceID || got.IdentityConfidence != 0.75 || got.IdentityReason != event.IdentityReason ||
		got.SensorID != "sensor-a" || got.Disposition != "suppressed" || got.SuppressionRuleID != "synthetic-rule-54" {
		t.Fatalf("identity fields did not round-trip: %+v", got)
	}
}

func snapshotQuery(t *testing.T, db *DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result [][]string
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		row := make([]string, len(values))
		for i, value := range values {
			switch v := value.(type) {
			case []byte:
				row[i] = string(v)
			default:
				row[i] = fmt.Sprint(v)
			}
		}
		result = append(result, row)
	}
	encoded, _ := json.Marshal(result)
	return string(encoded)
}

func TestSoftMergeSplitIsAuditedExactUndo(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	targetID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.60", "00:00:5E:00:53:60", "target-host")
	sourceID := observeAsset(t, db, base.Add(time.Minute), "sensor-a", "lan", "192.0.2.61", "00:00:5E:00:53:61", "source-host")

	targetBefore := []string{
		snapshotQuery(t, db, `SELECT * FROM devices WHERE device_id=?`, targetID),
		snapshotQuery(t, db, `SELECT * FROM device_signals WHERE device_id=? ORDER BY field,source`, targetID),
		snapshotQuery(t, db, `SELECT * FROM device_networks WHERE device_id=? ORDER BY segment`, targetID),
	}
	action, err := db.MergeDevices(context.Background(), sourceID, targetID, "same synthetic appliance", "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := db.CanonicalDeviceID(context.Background(), sourceID); err != nil || canonical != targetID {
		t.Fatalf("merge redirect = %q err=%v", canonical, err)
	}
	mergedList, err := db.ListDevices()
	if err != nil || len(mergedList) != 1 || mergedList[0].DeviceID != targetID || mergedList[0].Hostname != "source-host" {
		t.Fatalf("canonical merged read did not aggregate source signals: %+v err=%v", mergedList, err)
	}
	var sourceRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE device_id=?`, sourceID).Scan(&sourceRows); err != nil || sourceRows != 1 {
		t.Fatal("soft merge deleted its source device")
	}

	split, err := db.UndoDeviceMerge(context.Background(), action.ActionID, "undo test merge", "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if split.ActionType != "split" {
		t.Fatalf("undo action = %+v", split)
	}
	splitList, err := db.ListDevices()
	if err != nil || len(splitList) != 2 {
		t.Fatalf("split did not restore two visible devices: %+v err=%v", splitList, err)
	}
	var redirect sql.NullString
	if err := db.QueryRow(`SELECT merged_into_device_id FROM devices WHERE device_id=?`, sourceID).Scan(&redirect); err != nil || redirect.Valid {
		t.Fatalf("split did not clear redirect: %+v err=%v", redirect, err)
	}
	targetAfter := []string{
		snapshotQuery(t, db, `SELECT * FROM devices WHERE device_id=?`, targetID),
		snapshotQuery(t, db, `SELECT * FROM device_signals WHERE device_id=? ORDER BY field,source`, targetID),
		snapshotQuery(t, db, `SELECT * FROM device_networks WHERE device_id=? ORDER BY segment`, targetID),
	}
	if !reflect.DeepEqual(targetBefore, targetAfter) {
		t.Fatalf("merge/split mutated target state\nbefore=%v\nafter=%v", targetBefore, targetAfter)
	}
	var mergeUndoneBy string
	if err := db.QueryRow(`SELECT undone_by_action_id FROM device_identity_actions WHERE action_id=?`, action.ActionID).Scan(&mergeUndoneBy); err != nil || mergeUndoneBy != split.ActionID {
		t.Fatalf("merge audit not linked to split: %q err=%v", mergeUndoneBy, err)
	}
}

func TestListDevicesIdentitySummaryTransitionsAndRedirectAggregation(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	sourceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.70", "", "")

	assertOne := func(wantStatus string, wantNeeds bool) models.Device {
		t.Helper()
		devices, err := db.ListDevices()
		if err != nil || len(devices) != 1 {
			t.Fatalf("list devices: %+v err=%v", devices, err)
		}
		device := devices[0]
		if device.IdentityStatus != wantStatus || device.NeedsIdentification != wantNeeds || device.CanonicalDeviceID != device.DeviceID {
			t.Fatalf("identity summary = %+v, want status=%s needs=%v", device, wantStatus, wantNeeds)
		}
		return device
	}
	unresolved := assertOne("unresolved", true)
	if unresolved.IdentityReason != "no_current_identity_evidence" || unresolved.IdentityConfidence != 0 {
		t.Fatalf("unresolved summary = %+v", unresolved)
	}

	// A service type alone is intentionally weak and should enter review.
	if _, err := db.ObserveDevice(DeviceObservation{Host: discovery.DiscoveredHost{
		IPAddress: "192.0.2.70", Services: []string{"_synthetic._tcp"}, DiscoverySource: "passive_mdns",
	}, Segment: "lan", SensorID: "sensor-a", ObservedAt: base.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	low := assertOne("low_confidence", true)
	if low.IdentityConfidence != 0.45 {
		t.Fatalf("low-confidence summary = %+v", low)
	}

	if _, err := db.ConfirmDeviceIdentity(context.Background(), sourceID,
		DeviceIdentityEvidenceInput{Type: "hostname", Value: "confirmed-device-70"},
		"lan", "sensor-a", "test-admin", "verified local inventory", base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	confirmed := assertOne("confirmed", false)
	if confirmed.IdentityConfidence != 1 || confirmed.IdentityReason != "operator_confirmed_identity" {
		t.Fatalf("confirmed summary = %+v", confirmed)
	}

	// Redirect the confirmed source into an otherwise unidentified target. The
	// target's read-time summary must aggregate the child's confirmation.
	targetID := observeAsset(t, db, base, "sensor-a", "iot", "198.51.100.70", "", "")
	if _, err := db.MergeDevices(context.Background(), sourceID, targetID, "same synthetic asset", "test-admin"); err != nil {
		t.Fatal(err)
	}
	devices, err := db.ListDevices()
	if err != nil || len(devices) != 1 || devices[0].DeviceID != targetID || devices[0].IdentityStatus != "confirmed" || devices[0].NeedsIdentification {
		t.Fatalf("redirected identity summary was not aggregated: %+v err=%v", devices, err)
	}
	bySource, err := db.GetDeviceByID(context.Background(), sourceID)
	if err != nil || bySource == nil || bySource.DeviceID != targetID || bySource.IdentityStatus != "confirmed" {
		t.Fatalf("canonical GetDeviceByID = %+v err=%v", bySource, err)
	}
	finalID := observeAsset(t, db, base, "sensor-a", "guest", "203.0.113.70", "", "")
	if _, err := db.MergeDevices(context.Background(), targetID, finalID, "second canonical redirect", "test-admin"); err != nil {
		t.Fatal(err)
	}
	devices, err = db.ListDevices()
	if err != nil || len(devices) != 1 || devices[0].DeviceID != finalID || devices[0].IdentityStatus != "confirmed" {
		t.Fatalf("recursive redirected identity summary was not aggregated: %+v err=%v", devices, err)
	}
	bySource, err = db.GetDeviceByID(context.Background(), sourceID)
	if err != nil || bySource == nil || bySource.DeviceID != finalID {
		t.Fatalf("recursive canonical GetDeviceByID = %+v err=%v", bySource, err)
	}
}

func TestListDevicesFlagsSharedStrongEvidenceConflict(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	firstID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.71", "", "")
	secondID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.72", "", "")
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	shared := DeviceIdentityEvidenceInput{Type: "dhcp_client_id", Value: "synthetic-shared-client-71", Source: "test", Confidence: 0.95, Sensitive: true}
	if _, err := db.upsertIdentityEvidenceTx(tx, firstID, "lan", "sensor-a", shared, base, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.upsertIdentityEvidenceTx(tx, secondID, "lan", "sensor-a", shared, base, false); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	devices, err := db.ListDevices()
	if err != nil || len(devices) != 2 {
		t.Fatalf("list conflict devices: %+v err=%v", devices, err)
	}
	for _, device := range devices {
		if device.IdentityStatus != "conflict" || !device.NeedsIdentification || device.IdentityConfidence != 0 {
			t.Fatalf("shared stable identity was not surfaced as conflict: %+v", device)
		}
	}
}

func TestListDevicesStrongMACIsHighConfidence(t *testing.T) {
	db := newCorrelationDB(t)
	id := observeAsset(t, db, time.Now().UTC(), "sensor-a", "lan", "192.0.2.73", "00:00:5E:00:53:73", "host-73")
	devices, err := db.ListDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("list devices: %+v err=%v", devices, err)
	}
	device := devices[0]
	if device.DeviceID != id || device.IdentityConfidence != 0.95 || device.IdentityStatus != "high_confidence" ||
		device.IdentityReason != "mac_identity_evidence" || device.NeedsIdentification {
		t.Fatalf("strong MAC summary = %+v", device)
	}
}

func TestListActiveDeviceMergesTracksUndoAndCanonicalTarget(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	sourceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.80", "00:00:5E:00:53:80", "source-80")
	targetID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.81", "00:00:5E:00:53:81", "target-81")
	merge, err := db.MergeDevices(context.Background(), sourceID, targetID, "duplicate synthetic record", "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	actions, err := db.ListActiveDeviceMerges(context.Background())
	if err != nil || len(actions) != 1 {
		t.Fatalf("active merges = %+v err=%v", actions, err)
	}
	action := actions[0]
	if action.ActionID != merge.ActionID || action.SourceDeviceID != sourceID || action.TargetDeviceID != targetID ||
		action.CanonicalTargetDeviceID != targetID || action.SourceDisplayName == "" || action.TargetDisplayName == "" {
		t.Fatalf("active merge projection = %+v", action)
	}
	thirdID := observeAsset(t, db, base, "sensor-a", "iot", "198.51.100.82", "00:00:5E:00:53:82", "target-82")
	secondMerge, err := db.MergeDevices(context.Background(), targetID, thirdID, "canonical target moved", "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	actions, err = db.ListActiveDeviceMerges(context.Background())
	if err != nil || len(actions) != 2 {
		t.Fatalf("chained active merges = %+v err=%v", actions, err)
	}
	foundOriginal := false
	for _, current := range actions {
		if current.ActionID == merge.ActionID {
			foundOriginal = true
			if current.CanonicalTargetDeviceID != thirdID || current.TargetDisplayName == "" {
				t.Fatalf("original merge did not follow canonical target: %+v", current)
			}
		}
	}
	if !foundOriginal {
		t.Fatal("original active merge missing after target redirect")
	}
	if _, err := db.UndoDeviceMerge(context.Background(), secondMerge.ActionID, "restore first target", "test-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UndoDeviceMerge(context.Background(), merge.ActionID, "incorrect merge", "test-admin"); err != nil {
		t.Fatal(err)
	}
	actions, err = db.ListActiveDeviceMerges(context.Background())
	if err != nil || len(actions) != 0 {
		t.Fatalf("undone merge remained active: %+v err=%v", actions, err)
	}
}
