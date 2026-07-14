package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// TestProvisionSensorToken_Atomicity is the beta-gate B1a store-level guarantee:
// at most one active sensor token per sensor, enforced transactionally so a
// failed provision (e.g. a second active insert that violates the unique index)
// rolls back cleanly and leaves the existing credential untouched.
func TestProvisionSensorToken_Atomicity(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "provision.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	sensor := models.Sensor{SensorID: "s1", Hostname: "h", OS: "linux", Arch: "amd64", CIDR: "192.168.1.0/24", Version: "t"}

	active := func() int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id=? AND scope='sensor' AND revoked=0`, "s1").Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	mint := func() (string, auth.Token) {
		raw, tok, err := auth.GenerateToken(auth.ScopeSensor, "s1", "test")
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		return raw, tok
	}

	// First provision (no existing token to revoke) → exactly one active token.
	raw1, tok1 := mint()
	if err := db.ProvisionSensorToken(sensor, tok1, false); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if active() != 1 {
		t.Fatalf("after first provision want 1 active, got %d", active())
	}

	// Provisioning as a NEW enrollment again must fail the identity precondition
	// (the row already exists) — ErrSensorExists — and roll back, leaving the first
	// token intact. This is the guard that stops a generic code re-enrolling an
	// existing (even revoked) sensor.
	_, tok2 := mint()
	if err := db.ProvisionSensorToken(sensor, tok2, false); !errors.Is(err, ErrSensorExists) {
		t.Fatalf("expected ErrSensorExists provisioning a new token for an existing identity, got %v", err)
	}
	if active() != 1 {
		t.Fatalf("after a failed second provision want 1 active (rollback), got %d", active())
	}
	if _, err := db.ValidateToken(raw1); err != nil {
		t.Fatalf("the original token must survive a failed provision: %v", err)
	}

	// A reset against a NON-existent identity must fail with ErrSensorNotFound.
	_, tokX, err := auth.GenerateToken(auth.ScopeSensor, "ghost", "test")
	if err != nil {
		t.Fatalf("generate ghost token: %v", err)
	}
	if err := db.ProvisionSensorToken(models.Sensor{SensorID: "ghost"}, tokX, true); !errors.Is(err, ErrSensorNotFound) {
		t.Fatalf("expected ErrSensorNotFound resetting a non-existent sensor, got %v", err)
	}

	// A reset (revokeExisting=true) succeeds: old revoked, new active, still one.
	raw3, tok3 := mint()
	if err := db.ProvisionSensorToken(sensor, tok3, true); err != nil {
		t.Fatalf("reset provision: %v", err)
	}
	if active() != 1 {
		t.Fatalf("after reset want 1 active, got %d", active())
	}
	if _, err := db.ValidateToken(raw3); err != nil {
		t.Fatalf("the new token must validate: %v", err)
	}
	if _, err := db.ValidateToken(raw1); err == nil {
		t.Fatal("the old token must be revoked after a reset")
	}
}
