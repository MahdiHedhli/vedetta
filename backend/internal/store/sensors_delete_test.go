package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// TestDeleteSensor_GuardsAndCascade covers the dashboard "Remove sensor" flow:
//   - a ghost sensor -> ErrSensorNotFound;
//   - a non-primary sensor is removed AND its api_tokens rows are HARD-deleted
//     (a soft revoke would leave the NO-ACTION FK and fail the parent delete);
//   - the last remaining primary can NOT be removed (would leave zero primaries)
//     and survives the refusal.
func TestDeleteSensor_GuardsAndCascade(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "delete-sensor.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	s1 := models.Sensor{SensorID: "s1", Hostname: "primary", OS: "linux", Arch: "amd64", CIDR: "192.0.2.0/24", Version: "t"}
	s2 := models.Sensor{SensorID: "s2", Hostname: "stale", OS: "darwin", Arch: "arm64", CIDR: "192.0.2.0/24", Version: "t"}
	if err := db.RegisterSensor(s1); err != nil {
		t.Fatalf("register s1: %v", err)
	}
	// s2 registers via the token-provision path (creates the identity + its auth token
	// together), so s2 owns an api_tokens row — the FK-cascade case DeleteSensor must
	// hard-delete.
	_, tok, err := auth.GenerateToken(auth.ScopeSensor, "s2", "test")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if err := db.ProvisionSensorToken(s2, tok, false); err != nil {
		t.Fatalf("provision s2: %v", err)
	}
	if err := db.SetPrimarySensor("s1"); err != nil {
		t.Fatalf("set primary s1: %v", err)
	}

	// Ghost -> ErrSensorNotFound.
	if err := db.DeleteSensor("ghost"); !errors.Is(err, ErrSensorNotFound) {
		t.Fatalf("delete ghost: got %v, want ErrSensorNotFound", err)
	}

	// Non-primary with a token -> removed, token row physically gone.
	if err := db.DeleteSensor("s2"); err != nil {
		t.Fatalf("delete non-primary s2: %v", err)
	}
	var sensorCount, tokenCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id='s2'`).Scan(&sensorCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id='s2'`).Scan(&tokenCount); err != nil {
		t.Fatal(err)
	}
	if sensorCount != 0 {
		t.Fatalf("s2 sensor row not deleted (count=%d)", sensorCount)
	}
	if tokenCount != 0 {
		t.Fatalf("s2 token rows not hard-deleted (count=%d) — a NO-ACTION FK would have blocked the delete", tokenCount)
	}

	// s1 is now the only (primary) sensor -> refuse, and it survives.
	if err := db.DeleteSensor("s1"); !errors.Is(err, ErrLastPrimarySensor) {
		t.Fatalf("delete last primary: got %v, want ErrLastPrimarySensor", err)
	}
	var s1Count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id='s1'`).Scan(&s1Count); err != nil {
		t.Fatal(err)
	}
	if s1Count != 1 {
		t.Fatalf("s1 must survive a refused delete, count=%d", s1Count)
	}
}
