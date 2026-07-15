package store

import (
	"context"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

func resolveStrengthEvidence(t *testing.T, db *DB, at time.Time, sensor, segment, kind, value string) DeviceIdentityResolution {
	t.Helper()
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: at, Segment: segment, SensorID: sensor,
		Evidence: []DeviceIdentityEvidenceInput{{Type: kind, Value: value}},
	})
	if err != nil {
		t.Fatalf("resolve %s strength at %s: %v", kind, at, err)
	}
	return got
}

func resolveStrengthMAC(t *testing.T, db *DB, at time.Time, sensor, segment, mac string) DeviceIdentityResolution {
	t.Helper()
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: at, MACAddress: mac, Segment: segment, SensorID: sensor,
	})
	if err != nil {
		t.Fatalf("resolve MAC strength at %s: %v", at, err)
	}
	return got
}

func resolveStrengthIP(t *testing.T, db *DB, at time.Time, sensor, segment, ip string) DeviceIdentityResolution {
	t.Helper()
	got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
		Timestamp: at, IPAddress: ip, Segment: segment, SensorID: sensor,
	})
	if err != nil {
		t.Fatalf("resolve address strength at %s: %v", at, err)
	}
	return got
}

func TestStrengthHistoryCachePromotionIsNotRetroactive(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	strongAt := base.Add(time.Hour)
	historicalAt := base.Add(30 * time.Second)
	ip := "192.0.2.200"
	mac := "00:00:5E:00:53:C8"

	created, err := db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: base,
	})
	if err != nil || !created {
		t.Fatalf("weak cache observation: created=%v err=%v", created, err)
	}
	var deviceID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address = ?`, ip).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}

	created, err = db.ObserveDevice(DeviceObservation{
		Host: discovery.DiscoveredHost{
			IPAddress: ip, MACAddress: mac, Hostname: "later-confirmed",
			Status: "up", DiscoverySource: "passive_dhcp",
		},
		Segment: "lan", SensorID: "sensor-a", ObservedAt: strongAt,
	})
	if err != nil || created {
		t.Fatalf("strong corroboration: created=%v err=%v", created, err)
	}

	if got := resolveStrengthMAC(t, db, historicalAt, "sensor-a", "lan", mac); got.DeviceID != "" {
		t.Fatalf("later DHCP evidence retroactively resolved cache MAC: %+v", got)
	}
	if got := resolveStrengthIP(t, db, historicalAt, "sensor-a", "lan", ip); got.DeviceID != deviceID || got.Confidence != arpCacheIdentityConfidence {
		t.Fatalf("later DHCP evidence retroactively promoted cache address: %+v", got)
	}
	if got := resolveStrengthMAC(t, db, strongAt.Add(time.Second), "sensor-a", "lan", mac); got.DeviceID != deviceID || got.Confidence != 0.90 {
		t.Fatalf("post-corroboration MAC did not resolve strongly: %+v", got)
	}
	if got := resolveStrengthIP(t, db, strongAt.Add(time.Second), "sensor-a", "lan", ip); got.DeviceID != deviceID || got.Confidence != 0.75 {
		t.Fatalf("post-corroboration address did not use stronger evidence: %+v", got)
	}

	// Current projections still retain their best aggregate for inventory APIs.
	var source string
	var confidence float64
	if err := db.QueryRow(`SELECT source, confidence FROM device_identity_evidence
		WHERE device_id = ? AND evidence_type = 'mac'`, deviceID).Scan(&source, &confidence); err != nil {
		t.Fatal(err)
	}
	if source != "passive_dhcp" || confidence != 0.95 {
		t.Fatalf("current identity aggregate regressed: source=%q confidence=%.2f", source, confidence)
	}
}

func TestStrengthHistoryPreExistingLowToHighPromotionIsTemporal(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	strongAt := base.Add(time.Hour)
	ip := "192.0.2.201"
	mac := "00:00:5E:00:53:C9"
	clientID := "synthetic-client-201"

	observe := func(at time.Time, discoverySource string, confidence float64) {
		t.Helper()
		if _, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, DiscoverySource: discoverySource,
				IdentityEvidence: []discovery.IdentityEvidence{{
					Type: "dhcp_client_id", Value: clientID, Source: "passive_dhcp",
					Confidence: confidence, Sensitive: true,
				}},
			},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
		}); err != nil {
			t.Fatalf("observe strength %.2f at %s: %v", confidence, at, err)
		}
	}
	observe(base, "nmap_active", 0.50)
	var deviceID string
	if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address = ?`, ip).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	observe(strongAt, "passive_mdns", 0.95)

	historicalAt := base.Add(time.Minute)
	if got := resolveStrengthEvidence(t, db, historicalAt, "sensor-a", "lan", "dhcp_client_id", clientID); got.DeviceID != "" {
		t.Fatalf("later stable evidence retroactively resolved old event: %+v", got)
	}
	if got := resolveStrengthIP(t, db, historicalAt, "sensor-a", "lan", ip); got.DeviceID != deviceID || got.Confidence != 0.75 {
		t.Fatalf("later address evidence retroactively raised confidence: %+v", got)
	}
	if got := resolveStrengthEvidence(t, db, strongAt.Add(time.Minute), "sensor-a", "lan", "dhcp_client_id", clientID); got.DeviceID != deviceID || got.Reason != "stable_identity_evidence" {
		t.Fatalf("post-upgrade stable evidence did not resolve: %+v", got)
	}
	if got := resolveStrengthIP(t, db, strongAt.Add(time.Minute), "sensor-a", "lan", ip); got.DeviceID != deviceID || got.Confidence != 0.90 {
		t.Fatalf("post-upgrade address confidence = %+v", got)
	}
}

func TestStrengthHistoryOutOfOrderUsesObservationTime(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	lateArrivalTime := base.Add(time.Hour)
	ip := "192.0.2.202"
	mac := "00:00:5E:00:53:CA"
	clientID := "synthetic-client-202"

	observe := func(at time.Time, source string, confidence float64) string {
		t.Helper()
		if _, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, DiscoverySource: source,
				IdentityEvidence: []discovery.IdentityEvidence{{
					Type: "dhcp_client_id", Value: clientID, Source: "passive_dhcp",
					Confidence: confidence, Sensitive: true,
				}},
			},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
		}); err != nil {
			t.Fatalf("out-of-order observation: %v", err)
		}
		var id string
		if err := db.QueryRow(`SELECT device_id FROM devices WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1`, ip).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	newerID := observe(lateArrivalTime, "nmap_active", 0.50)
	olderID := observe(base, "passive_mdns", 0.95) // arrives second, observed earlier
	if olderID != newerID {
		t.Fatalf("out-of-order corroboration split device: newer=%s older=%s", newerID, olderID)
	}
	at := base.Add(time.Minute)
	if got := resolveStrengthEvidence(t, db, at, "sensor-a", "lan", "dhcp_client_id", clientID); got.DeviceID != newerID || got.Reason != "stable_identity_evidence" {
		t.Fatalf("backfilled strong observation was keyed to arrival order: %+v", got)
	}
	if got := resolveStrengthIP(t, db, at, "sensor-a", "lan", ip); got.DeviceID != newerID || got.Confidence != 0.90 {
		t.Fatalf("backfilled address strength was keyed to arrival order: %+v", got)
	}
}

func TestStrengthHistoryOperatorConfirmationIsNotRetroactive(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 13, 0, 0, 0, time.UTC)
	confirmAt := base.Add(time.Hour)
	clientID := "synthetic-client-203"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.203", "00:00:5E:00:53:CB", "host-203",
		evidence("dhcp_client_id", clientID, 0.95))

	if _, err := db.ConfirmDeviceIdentity(context.Background(), deviceID, DeviceIdentityEvidenceInput{
		Type: "dhcp_client_id", Value: clientID, Source: "operator", Confidence: 1, Sensitive: true,
	}, "lan", "sensor-a", "test-admin", "synthetic confirmation", confirmAt); err != nil {
		t.Fatalf("confirm identity: %v", err)
	}

	if got := resolveStrengthEvidence(t, db, base.Add(time.Minute), "sensor-a", "lan", "dhcp_client_id", clientID); got.DeviceID != deviceID || got.Reason != "stable_identity_evidence" || got.Confidence != 0.95 {
		t.Fatalf("operator confirmation applied before confirmation time: %+v", got)
	}
	if got := resolveStrengthEvidence(t, db, confirmAt.Add(time.Minute), "sensor-a", "lan", "dhcp_client_id", clientID); got.DeviceID != deviceID || got.Reason != "operator_confirmed_identity" || got.Confidence != 1 {
		t.Fatalf("operator confirmation unavailable after confirmation time: %+v", got)
	}
}

func TestStrongIdentityEvidenceRemainsDurableAcrossObservationGap(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 13, 30, 0, 0, time.UTC)
	returnAt := base.Add(14 * 24 * time.Hour)
	mac := "00:00:5E:00:53:CD"
	clientID := "synthetic-client-returning"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.205", mac, "host-205",
		evidence("dhcp_client_id", clientID, 0.95))

	if got := resolveStrengthEvidence(t, db, returnAt, "sensor-a", "lan", "dhcp_client_id", clientID); got.DeviceID != deviceID || got.Reason != "stable_identity_evidence" {
		t.Fatalf("returning stable identity split after observation gap: %+v", got)
	}
	if got := resolveStrengthMAC(t, db, returnAt, "sensor-a", "lan", mac); got.DeviceID != deviceID || got.Reason != "mac_identity_evidence" {
		t.Fatalf("returning MAC identity split after observation gap: %+v", got)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := db.macConflictsAt(tx, deviceID, "00:00:5E:00:53:CE", returnAt)
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if !conflict {
		t.Fatal("durable known MAC stopped vetoing a contradictory merge after an observation gap")
	}
}

func TestStrengthHistorySameTimestampReplayIsIdempotent(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 14, 0, 0, 0, time.UTC)
	strongAt := base.Add(time.Hour)
	ip := "192.0.2.204"
	mac := "00:00:5E:00:53:CC"
	clientID := "synthetic-client-204"

	observe := func(at time.Time, source string, confidence float64) {
		t.Helper()
		if _, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, DiscoverySource: source,
				IdentityEvidence: []discovery.IdentityEvidence{{
					Type: "dhcp_client_id", Value: clientID, Source: "passive_dhcp",
					Confidence: confidence, Sensitive: true,
				}},
			},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
		}); err != nil {
			t.Fatalf("observe replay fixture: %v", err)
		}
	}
	observe(base, "nmap_active", 0.50)
	observe(base, "nmap_active", 0.50)
	observe(strongAt, "passive_mdns", 0.95)
	observe(strongAt, "passive_mdns", 0.95)
	// Runtime schema self-heal runs on every restart. It must not use the now-high
	// aggregate row to manufacture a high baseline at the original valid_from.
	if err := db.ensureAssetCenteredSchema(); err != nil {
		t.Fatalf("repeat strength-history ensure: %v", err)
	}

	var evidenceChanges, addressChanges, evidenceValidity, addressValidity int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_strength s
		JOIN device_identity_evidence e ON e.evidence_id = s.evidence_id
		WHERE e.evidence_type = 'dhcp_client_id'`).Scan(&evidenceChanges); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_strength s
		JOIN device_address_history h ON h.binding_id = s.binding_id
		WHERE h.address_type = 'ip' AND h.address_value = ?`, ip).Scan(&addressChanges); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_identity_evidence_validity v
		JOIN device_identity_evidence e ON e.evidence_id = v.evidence_id
		WHERE e.evidence_type = 'dhcp_client_id'`).Scan(&evidenceValidity); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_validity v
		JOIN device_address_history h ON h.binding_id = v.binding_id
		WHERE h.address_type = 'ip' AND h.address_value = ?`, ip).Scan(&addressValidity); err != nil {
		t.Fatal(err)
	}
	if evidenceChanges != 2 || addressChanges != 2 {
		t.Fatalf("same-time replay grew strength history: evidence=%d address=%d, want 2/2", evidenceChanges, addressChanges)
	}
	if evidenceValidity != 1 || addressValidity != 1 {
		t.Fatalf("same-time replay grew validity history: evidence=%d address=%d, want 1/1",
			evidenceValidity, addressValidity)
	}
}

func TestValidityHistoryLaterAliasRefreshIsNotRetroactive(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 17, 0, 0, 0, time.UTC)
	hostname := "synthetic-alias-210"
	option55 := "1,3,6,15,119,252"
	ip := "192.0.2.210"
	mac := "00:00:5E:00:53:D2"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", ip, mac, hostname,
		evidence("dhcp_option_55", option55, 0.70))

	resolve := func(at time.Time) DeviceIdentityResolution {
		t.Helper()
		got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
			Timestamp: at, Segment: "lan", SensorID: "sensor-a",
			Evidence: []DeviceIdentityEvidenceInput{
				{Type: "hostname", Value: hostname},
				{Type: "dhcp_option_55", Value: option55},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	staleAt := base.Add(8 * 24 * time.Hour)
	if got := resolve(staleAt); got.DeviceID != "" {
		t.Fatalf("stale aliases unexpectedly resolved before refresh: %+v", got)
	}
	refreshAt := base.Add(10 * 24 * time.Hour)
	if got := observeAsset(t, db, refreshAt, "sensor-a", "lan", ip, mac, hostname,
		evidence("dhcp_option_55", option55, 0.70)); got != deviceID {
		t.Fatalf("alias refresh split device: got %q want %q", got, deviceID)
	}
	if err := db.ensureAssetCenteredSchema(); err != nil {
		t.Fatalf("repeat schema ensure after alias gap: %v", err)
	}
	if got := resolve(staleAt); got.DeviceID != "" {
		t.Fatalf("later alias refresh changed historical resolution: %+v", got)
	}
	if got := resolve(refreshAt.Add(time.Second)); got.DeviceID != deviceID || got.Reason != "corroborated_identity_evidence" {
		t.Fatalf("fresh aliases did not resolve after refresh: %+v", got)
	}
}

func TestValidityHistoryLaterAddressRefreshIsNotRetroactive(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC)
	ip := "192.0.2.211"
	mac := "00:00:5E:00:53:D3"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", ip, mac, "address-211")
	staleAt := base.Add(25 * time.Hour)
	if got := resolveStrengthIP(t, db, staleAt, "sensor-a", "lan", ip); got.DeviceID != "" {
		t.Fatalf("stale address unexpectedly resolved before refresh: %+v", got)
	}
	refreshAt := base.Add(30 * time.Hour)
	if got := observeAsset(t, db, refreshAt, "sensor-a", "lan", ip, mac, "address-211"); got != deviceID {
		t.Fatalf("address refresh split device: got %q want %q", got, deviceID)
	}
	if err := db.ensureAssetCenteredSchema(); err != nil {
		t.Fatalf("repeat schema ensure after address gap: %v", err)
	}
	if got := resolveStrengthIP(t, db, staleAt, "sensor-a", "lan", ip); got.DeviceID != "" {
		t.Fatalf("later address refresh changed historical resolution: %+v", got)
	}
	if got := resolveStrengthIP(t, db, refreshAt.Add(time.Hour), "sensor-a", "lan", ip); got.DeviceID != deviceID {
		t.Fatalf("fresh address did not resolve after refresh: %+v", got)
	}
}

func TestClosedAddressIntervalDoesNotFillStaleObservationGap(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 30, 0, 0, time.UTC)
	ip := "192.0.2.214"
	firstID := observeAsset(t, db, base, "sensor-a", "lan", ip, "00:00:5E:00:53:D7", "first-owner")
	gapAt := base.Add(25 * time.Hour)
	if got := resolveStrengthIP(t, db, gapAt, "sensor-a", "lan", ip); got.DeviceID != "" {
		t.Fatalf("open stale address unexpectedly resolved before reuse: %+v", got)
	}
	secondID := observeAsset(t, db, base.Add(30*time.Hour), "sensor-a", "lan", ip,
		"00:00:5E:00:53:D8", "second-owner", evidence("dhcp_client_id", "second-owner-214", 0.95))
	if secondID == firstID {
		t.Fatal("address-reuse fixture collapsed distinct owners")
	}
	if got := resolveStrengthIP(t, db, gapAt, "sensor-a", "lan", ip); got.DeviceID != "" {
		t.Fatalf("closing old address interval filled stale gap: %+v", got)
	}
}

func TestClosedAliasEvidenceDoesNotFillStaleObservationGap(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 18, 45, 0, 0, time.UTC)
	hostname := "closed-alias-215"
	option55 := "1,3,6,15,31,33,43,44,46,47,121"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", "192.0.2.215",
		"00:00:5E:00:53:D9", hostname, evidence("dhcp_option_55", option55, 0.70))
	gapAt := base.Add(8 * 24 * time.Hour)
	resolve := func() DeviceIdentityResolution {
		t.Helper()
		got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
			Timestamp: gapAt, Segment: "lan", SensorID: "sensor-a",
			Evidence: []DeviceIdentityEvidenceInput{
				{Type: "hostname", Value: hostname},
				{Type: "dhcp_option_55", Value: option55},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := resolve(); got.DeviceID != "" {
		t.Fatalf("open stale aliases unexpectedly resolved: %+v", got)
	}
	if _, err := db.Exec(`UPDATE device_identity_evidence SET valid_until = ?
		WHERE device_id = ? AND evidence_type IN ('hostname','dhcp_option_55')`,
		base.Add(10*24*time.Hour), deviceID); err != nil {
		t.Fatal(err)
	}
	if got := resolve(); got.DeviceID != "" {
		t.Fatalf("closing alias evidence filled stale gap: %+v", got)
	}
}

func TestAddressValidityWindowsStayCompactAndMergeOutOfOrder(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC)
	ip := "192.0.2.212"
	mac := "00:00:5E:00:53:D4"
	observeCache := func(at time.Time) {
		t.Helper()
		if _, err := db.ObserveDevice(DeviceObservation{
			Host: discovery.DiscoveredHost{
				IPAddress: ip, MACAddress: mac, Status: "observed", DiscoverySource: "arp_cache",
			},
			Segment: "lan", SensorID: "sensor-a", ObservedAt: at,
		}); err != nil {
			t.Fatalf("observe cache at %s: %v", at, err)
		}
	}
	observeCache(base)
	// One day of the default 30-second ARP-cache polling cadence must remain one
	// compact row rather than growing by 2,880 rows per device/day.
	for i := 1; i < 2880; i++ {
		observeCache(base.Add(time.Duration(i) * 30 * time.Second))
	}
	var bindingID string
	if err := db.QueryRow(`SELECT binding_id FROM device_address_history
		WHERE address_type='ip' AND address_value=? AND segment='lan' AND sensor_id='sensor-a'
		ORDER BY valid_from LIMIT 1`, ip).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	countWindows := func() int {
		t.Helper()
		var got int
		if err := db.QueryRow(`SELECT COUNT(*) FROM device_address_binding_validity
			WHERE binding_id=?`, bindingID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := countWindows(); got != 1 {
		t.Fatalf("30-second polling grew validity history to %d rows, want 1", got)
	}

	// Create a genuine gap, then deliver the missing bridge out of order. One
	// observation contributes an inclusive 24-hour window, so touching windows
	// are one continuous union.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	secondStart := base.Add(72*time.Hour - 30*time.Second)
	if err := recordAddressBindingValidityTx(tx, bindingID, secondStart); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := countWindows(); got != 2 {
		t.Fatalf("stale gap was collapsed: got %d windows, want 2", got)
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := recordAddressBindingValidityTx(tx, bindingID, secondStart.Add(-temporalAddressResolutionWindow)); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := countWindows(); got != 1 {
		t.Fatalf("out-of-order bridge did not merge validity union: got %d windows, want 1", got)
	}
}

func TestEventTimeMACConflictDoesNotUseLaterEvidence(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 20, 0, 0, 0, time.UTC)
	ip := "192.0.2.213"
	deviceID := observeAsset(t, db, base, "sensor-a", "lan", ip, "", "ip-only-213")
	incomingMAC := "00:00:5E:00:53:D5"
	knownLaterMAC := "00:00:5E:00:53:D6"
	requestAt := func(at time.Time) DeviceIdentityResolution {
		t.Helper()
		got, err := db.ResolveDeviceAt(context.Background(), DeviceIdentityResolutionRequest{
			Timestamp: at, IPAddress: ip, MACAddress: incomingMAC,
			Segment: "lan", SensorID: "sensor-a",
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	historicalAt := base.Add(time.Hour)
	if got := requestAt(historicalAt); got.DeviceID != deviceID {
		t.Fatalf("IP-only historical event did not resolve before MAC discovery: %+v", got)
	}
	learnAt := base.Add(2 * time.Hour)
	if got := observeAsset(t, db, learnAt, "sensor-a", "lan", ip, knownLaterMAC, "ip-only-213"); got != deviceID {
		t.Fatalf("later MAC discovery split fixture: got %q want %q", got, deviceID)
	}
	if got := requestAt(historicalAt); got.DeviceID != deviceID {
		t.Fatalf("later MAC discovery changed historical attribution: %+v", got)
	}
	if got := requestAt(learnAt.Add(time.Minute)); got.DeviceID != "" || got.Reason != "conflicting_address_mac" {
		t.Fatalf("post-discovery contradictory MAC was not vetoed: %+v", got)
	}
}

func TestIdentityFreshnessEndClampsNearSQLiteMaximum(t *testing.T) {
	nearMax := maxSQLiteIdentityTime.Add(-time.Minute)
	for _, window := range []time.Duration{temporalAddressResolutionWindow, mdnsNameRecencyWindow} {
		got, err := identityFreshnessEnd(nearMax, window)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(maxSQLiteIdentityTime) {
			t.Fatalf("freshness end for %s = %s, want clamp %s", window, got, maxSQLiteIdentityTime)
		}
	}
	if _, err := identityFreshnessEnd(maxSQLiteIdentityTime.Add(time.Millisecond), time.Hour); err == nil {
		t.Fatal("runtime accepted identity timestamp beyond SQLite maximum")
	}
}
