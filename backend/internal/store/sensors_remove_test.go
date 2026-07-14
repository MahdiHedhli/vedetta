package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// TestRemoveSensor_TombstonesAndReactivates guards the enrollment identity
// invariant as well as credential scope: removal retains the row and history,
// revokes only sensor credentials, and only an authenticated reset can return it.
func TestRemoveSensor_TombstonesAndReactivates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "remove-sensor.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	s1 := models.Sensor{SensorID: "s1", Hostname: "primary", OS: "linux", Arch: "amd64", CIDR: "192.0.2.0/24", Version: "t"}
	s2 := models.Sensor{SensorID: "s2", Hostname: "stale", OS: "darwin", Arch: "arm64", CIDR: "192.0.2.0/24", Version: "t"}
	if err := db.RegisterSensor(s1); err != nil {
		t.Fatalf("register s1: %v", err)
	}
	_, sensorToken, err := auth.GenerateToken(auth.ScopeSensor, "s2", "test")
	if err != nil {
		t.Fatalf("generate sensor token: %v", err)
	}
	if err := db.ProvisionSensorToken(s2, sensorToken, false); err != nil {
		t.Fatalf("provision s2: %v", err)
	}
	if err := db.SetPrimarySensor("s1"); err != nil {
		t.Fatalf("set primary s1: %v", err)
	}

	var firstSeen time.Time
	if err := db.QueryRow(`SELECT first_seen FROM sensors WHERE sensor_id='s2'`).Scan(&firstSeen); err != nil {
		t.Fatalf("read first_seen: %v", err)
	}

	// Simulate legacy non-sensor credentials that carried sensor_id before the
	// creation path rejected that combination. Removal must never touch them.
	now := time.Now().UTC()
	for _, scope := range []auth.TokenScope{auth.ScopeAdmin, auth.ScopeRead, auth.ScopeIngest} {
		if _, err := db.Exec(`
			INSERT INTO api_tokens(token_id,token_hash,scope,sensor_id,label,created_at,last_used,revoked)
			VALUES(?,?,?,?,?,?,?,0)
		`, "legacy-"+string(scope), "hash-"+string(scope), scope, "s2", "legacy", now, now); err != nil {
			t.Fatalf("insert legacy %s token: %v", scope, err)
		}
	}

	if _, err := db.RemoveSensor("ghost", "admin-1", "test"); !errors.Is(err, ErrSensorNotFound) {
		t.Fatalf("remove ghost: got %v, want ErrSensorNotFound", err)
	}

	removedAt, err := db.RemoveSensor("s2", "admin-1", "stale duplicate")
	if err != nil {
		t.Fatalf("remove non-primary s2: %v", err)
	}
	if removedAt.IsZero() {
		t.Fatal("remove returned a zero timestamp")
	}

	var storedRemoved sql.NullTime
	var status string
	var removalReason, removedByToken string
	if err := db.QueryRow(`
		SELECT removed_at, status, removal_reason, removed_by_token_id
		FROM sensors WHERE sensor_id='s2'
	`).Scan(&storedRemoved, &status, &removalReason, &removedByToken); err != nil {
		t.Fatalf("read tombstone: %v", err)
	}
	if !storedRemoved.Valid || status != "offline" {
		t.Fatalf("s2 was not tombstoned offline: removed=%v status=%q", storedRemoved, status)
	}
	if removalReason != "stale duplicate" || removedByToken != "admin-1" {
		t.Fatalf("removal metadata not persisted: reason=%q actor=%q", removalReason, removedByToken)
	}
	exists, err := db.SensorExists("s2")
	if err != nil || !exists {
		t.Fatalf("removed identity must continue to exist: exists=%v err=%v", exists, err)
	}
	listed, err := db.ListSensors()
	if err != nil {
		t.Fatalf("list active sensors: %v", err)
	}
	if len(listed) != 1 || listed[0].SensorID != "s1" {
		t.Fatalf("active list includes tombstone or lost primary: %#v", listed)
	}

	var revoked bool
	if err := db.QueryRow(`SELECT revoked FROM api_tokens WHERE token_id=?`, sensorToken.TokenID).Scan(&revoked); err != nil {
		t.Fatalf("read retained sensor token: %v", err)
	}
	if !revoked {
		t.Fatal("removed sensor credential remains active")
	}
	for _, scope := range []auth.TokenScope{auth.ScopeAdmin, auth.ScopeRead, auth.ScopeIngest} {
		var stillRevoked bool
		if err := db.QueryRow(`SELECT revoked FROM api_tokens WHERE token_id=?`, "legacy-"+string(scope)).Scan(&stillRevoked); err != nil {
			t.Fatalf("read legacy %s token: %v", scope, err)
		}
		if stillRevoked {
			t.Fatalf("sensor removal revoked unrelated %s credential", scope)
		}
	}

	var removedEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_lifecycle_events WHERE sensor_id='s2' AND event_type='removed'`).Scan(&removedEvents); err != nil {
		t.Fatalf("count removal audit events: %v", err)
	}
	if removedEvents != 1 {
		t.Fatalf("removal events=%d, want 1", removedEvents)
	}
	var eventActor, eventReason string
	if err := db.QueryRow(`
		SELECT actor, reason FROM sensor_lifecycle_events
		WHERE sensor_id='s2' AND event_type='removed'
	`).Scan(&eventActor, &eventReason); err != nil {
		t.Fatalf("read removal audit event: %v", err)
	}
	if eventActor != "admin-1" || eventReason != "stale duplicate" {
		t.Fatalf("removal audit metadata not persisted: actor=%q reason=%q", eventActor, eventReason)
	}
	removedAgain, err := db.RemoveSensor("s2", "admin-2", "repeat")
	if err != nil || !removedAgain.Equal(storedRemoved.Time.UTC()) {
		t.Fatalf("idempotent removal = %v, %v; want %v", removedAgain, err, storedRemoved.Time.UTC())
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_lifecycle_events WHERE sensor_id='s2' AND event_type='removed'`).Scan(&removedEvents); err != nil || removedEvents != 1 {
		t.Fatalf("idempotent removal duplicated audit event: count=%d err=%v", removedEvents, err)
	}

	// A generic/new provisioning attempt still sees the tombstone and cannot
	// reclaim the identity.
	_, genericToken, _ := auth.GenerateToken(auth.ScopeSensor, "s2", "generic")
	if err := db.ProvisionSensorToken(s2, genericToken, false); !errors.Is(err, ErrSensorExists) {
		t.Fatalf("generic provisioning of tombstone: got %v, want ErrSensorExists", err)
	}
	if err := db.RefreshSensorWithActiveToken(s2, sensorToken.TokenID); !errors.Is(err, ErrSensorRemoved) {
		t.Fatalf("refresh with pre-removal token: got %v, want ErrSensorRemoved", err)
	}

	// A deliberate reset reactivates the same row, preserves first_seen, and
	// creates exactly one fresh sensor credential plus an audit event.
	_, resetToken, _ := auth.GenerateToken(auth.ScopeSensor, "s2", "reset")
	if err := db.ProvisionSensorTokenWithActor(s2, resetToken, true, "bound-reset-code"); err != nil {
		t.Fatalf("reactivate s2: %v", err)
	}
	var removedAfter sql.NullTime
	var firstSeenAfter time.Time
	if err := db.QueryRow(`SELECT removed_at, first_seen FROM sensors WHERE sensor_id='s2'`).Scan(&removedAfter, &firstSeenAfter); err != nil {
		t.Fatalf("read reactivated sensor: %v", err)
	}
	if removedAfter.Valid || !firstSeenAfter.Equal(firstSeen) {
		t.Fatalf("reactivation changed identity history: removed=%v first=%v want=%v", removedAfter, firstSeenAfter, firstSeen)
	}
	var activeSensorTokens, reactivatedEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id='s2' AND scope='sensor' AND revoked=0`).Scan(&activeSensorTokens); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_lifecycle_events WHERE sensor_id='s2' AND event_type='reactivated'`).Scan(&reactivatedEvents); err != nil {
		t.Fatal(err)
	}
	if activeSensorTokens != 1 || reactivatedEvents != 1 {
		t.Fatalf("reactivation state: active tokens=%d events=%d, want 1/1", activeSensorTokens, reactivatedEvents)
	}

	// The current primary remains non-removable and unchanged.
	if _, err := db.RemoveSensor("s1", "admin-1", "test"); !errors.Is(err, ErrLastPrimarySensor) {
		t.Fatalf("remove primary: got %v, want ErrLastPrimarySensor", err)
	}
	var s1Removed sql.NullTime
	if err := db.QueryRow(`SELECT removed_at FROM sensors WHERE sensor_id='s1'`).Scan(&s1Removed); err != nil || s1Removed.Valid {
		t.Fatalf("primary changed after refused removal: removed=%v err=%v", s1Removed, err)
	}
}

func TestCreateTokenRejectsSensorIDOnNonSensorScope(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "token-scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, scope := range []auth.TokenScope{auth.ScopeAdmin, auth.ScopeRead, auth.ScopeIngest} {
		_, token, err := auth.GenerateToken(scope, "sensor-x", "invalid")
		if err != nil {
			t.Fatal(err)
		}
		if err := db.CreateToken(token); err == nil {
			t.Fatalf("CreateToken accepted sensor_id on %s token", scope)
		}
	}
}
