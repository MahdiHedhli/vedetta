package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

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
