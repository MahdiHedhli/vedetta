package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestSensorLifecycleConcurrentTransitionsPreserveInvariants(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "sensor-lifecycle-races.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	primary := models.Sensor{
		SensorID: "race-primary", Hostname: "primary", OS: "linux", Arch: "amd64",
		CIDR: "192.0.2.0/24", Version: "test",
	}
	if err := db.RegisterSensor(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}

	newSensor := func(t *testing.T, prefix string, i int) (models.Sensor, auth.Token) {
		t.Helper()
		sensor := models.Sensor{
			SensorID: fmt.Sprintf("%s-%02d", prefix, i), Hostname: fmt.Sprintf("host-%02d", i),
			OS: "linux", Arch: "arm64", CIDR: "198.51.100.0/24", Version: "test",
		}
		_, token, err := auth.GenerateToken(auth.ScopeSensor, sensor.SensorID, "race")
		if err != nil {
			t.Fatalf("generate sensor token: %v", err)
		}
		if err := db.ProvisionSensorToken(sensor, token, false); err != nil {
			t.Fatalf("provision sensor: %v", err)
		}
		return sensor, token
	}

	runTogether := func(left, right func() error) (error, error) {
		start := make(chan struct{})
		var results [2]error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; results[0] = left() }()
		go func() { defer wg.Done(); <-start; results[1] = right() }()
		close(start)
		wg.Wait()
		return results[0], results[1]
	}

	t.Run("remove versus authenticated refresh", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			sensor, token := newSensor(t, "refresh-race", i)
			removeErr, refreshErr := runTogether(
				func() error { _, err := db.RemoveSensor(sensor.SensorID, "admin-race", "test"); return err },
				func() error { return db.RefreshSensorWithActiveToken(sensor, token.TokenID) },
			)
			// Both operations may return nil when refresh commits first. If removal
			// committed first, refresh reports the retained tombstone.
			if removeErr != nil {
				t.Fatalf("iteration %d removal failed: %v (other=%v)", i, removeErr, refreshErr)
			}
			if refreshErr != nil && !errors.Is(refreshErr, ErrSensorRemoved) && !errors.Is(refreshErr, ErrSensorTokenInactive) {
				t.Fatalf("iteration %d refresh returned unexpected error: %v", i, refreshErr)
			}

			var removed sql.NullTime
			var activeTokens int
			if err := db.QueryRow(`SELECT removed_at FROM sensors WHERE sensor_id = ?`, sensor.SensorID).Scan(&removed); err != nil {
				t.Fatalf("iteration %d read tombstone: %v", i, err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id = ? AND scope = ? AND revoked = 0`, sensor.SensorID, auth.ScopeSensor).Scan(&activeTokens); err != nil {
				t.Fatalf("iteration %d count tokens: %v", i, err)
			}
			if !removed.Valid || activeTokens != 0 {
				t.Fatalf("iteration %d final refresh race state: removed=%v active_tokens=%d", i, removed.Valid, activeTokens)
			}
		}
	})

	t.Run("remove versus bound reset", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			sensor, _ := newSensor(t, "reset-race", i)
			_, resetToken, err := auth.GenerateToken(auth.ScopeSensor, sensor.SensorID, "reset")
			if err != nil {
				t.Fatalf("generate reset token: %v", err)
			}
			first, second := runTogether(
				func() error { _, err := db.RemoveSensor(sensor.SensorID, "admin-race", "test"); return err },
				func() error { return db.ProvisionSensorTokenWithActor(sensor, resetToken, true, "bound-reset-code") },
			)
			if first != nil || second != nil {
				t.Fatalf("iteration %d transition errors: %v / %v", i, first, second)
			}

			var activeIdentity, activeTokens int
			if err := db.QueryRow(`SELECT removed_at IS NULL FROM sensors WHERE sensor_id = ?`, sensor.SensorID).Scan(&activeIdentity); err != nil {
				t.Fatalf("iteration %d read identity: %v", i, err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id = ? AND scope = ? AND revoked = 0`, sensor.SensorID, auth.ScopeSensor).Scan(&activeTokens); err != nil {
				t.Fatalf("iteration %d count tokens: %v", i, err)
			}
			if activeIdentity != activeTokens || (activeIdentity != 0 && activeIdentity != 1) {
				t.Fatalf("iteration %d inconsistent final state: active_identity=%d active_tokens=%d", i, activeIdentity, activeTokens)
			}
		}
	})

	t.Run("remove versus promote", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			sensor, _ := newSensor(t, "promote-race", i)
			first, second := runTogether(
				func() error { _, err := db.RemoveSensor(sensor.SensorID, "admin-race", "test"); return err },
				func() error { return db.SetPrimarySensor(sensor.SensorID) },
			)
			valid := func(err error) bool {
				return err == nil || errors.Is(err, ErrLastPrimarySensor) || errors.Is(err, ErrSensorNotFound)
			}
			if !valid(first) || !valid(second) {
				t.Fatalf("iteration %d unexpected transition errors: %v / %v", i, first, second)
			}
			if first == nil && second == nil {
				t.Fatalf("iteration %d remove and promote both reported success", i)
			}

			var primaries int
			if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE removed_at IS NULL AND is_primary = TRUE`).Scan(&primaries); err != nil {
				t.Fatalf("iteration %d count primaries: %v", i, err)
			}
			if primaries != 1 {
				t.Fatalf("iteration %d active primaries=%d, want 1", i, primaries)
			}
		}
	})
}
