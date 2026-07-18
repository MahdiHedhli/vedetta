package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func newReplaceDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "replace.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// provisionSensor registers a sensor WITH a live sensor credential (so it is a
// valid replacement) and returns nothing; hostname lets tests model a redeploy.
func provisionSensor(t *testing.T, db *DB, id, hostname string) {
	t.Helper()
	s := models.Sensor{SensorID: id, Hostname: hostname, OS: "darwin", Arch: "arm64", CIDR: "192.0.2.0/24", Version: "t"}
	_, raw, err := auth.GenerateToken(auth.ScopeSensor, id, "test")
	if err != nil {
		t.Fatalf("generate token %s: %v", id, err)
	}
	if err := db.ProvisionSensorToken(s, raw, false); err != nil {
		t.Fatalf("provision %s: %v", id, err)
	}
}

func setLastSeen(t *testing.T, db *DB, id string, at time.Time) {
	t.Helper()
	if _, err := db.Exec(`UPDATE sensors SET last_seen = ? WHERE sensor_id = ?`, at, id); err != nil {
		t.Fatalf("set last_seen %s: %v", id, err)
	}
}

func activePrimaryCount(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE is_primary = TRUE AND removed_at IS NULL`).Scan(&n); err != nil {
		t.Fatalf("count primaries: %v", err)
	}
	return n
}

func TestEffectiveSensorStatus(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		lastSeen time.Time
		want     string
	}{
		{"just reported", now.Add(-10 * time.Second), "online"},
		{"at boundary", now.Add(-SensorOnlineWindow), "online"},
		{"just past boundary", now.Add(-SensorOnlineWindow - time.Second), "offline"},
		{"long silent", now.Add(-72 * time.Hour), "offline"},
		{"never reported", time.Time{}, "offline"},
		{"future clock skew", now.Add(30 * time.Second), "online"},
	}
	for _, c := range cases {
		if got := EffectiveSensorStatus(c.lastSeen, now); got != c.want {
			t.Errorf("%s: EffectiveSensorStatus = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestReplacePrimarySensor_HappyPath(t *testing.T) {
	db := newReplaceDB(t)
	now := time.Now().UTC()
	provisionSensor(t, db, "old", "HedhliMacStudio")
	provisionSensor(t, db, "new", "HedhliMacStudio") // same host = redeploy
	if err := db.SetPrimarySensor("old"); err != nil {
		t.Fatalf("set primary old: %v", err)
	}
	setLastSeen(t, db, "old", now.Add(-30*time.Minute)) // stale primary
	setLastSeen(t, db, "new", now)                      // online replacement

	newPrimary, removedAt, err := db.ReplacePrimarySensor("old", "new", "admin-1", "redeploy", false)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if newPrimary.SensorID != "new" || !newPrimary.IsPrimary {
		t.Fatalf("new primary = %+v, want new/is_primary", newPrimary)
	}
	if removedAt.IsZero() {
		t.Fatal("removedAt is zero")
	}
	if n := activePrimaryCount(t, db); n != 1 {
		t.Fatalf("active primary count = %d, want exactly 1", n)
	}
	// Old is tombstoned offline, no longer primary.
	var isPrimary bool
	var status string
	var removed *time.Time
	if err := db.QueryRow(`SELECT is_primary, status, removed_at FROM sensors WHERE sensor_id='old'`).Scan(&isPrimary, &status, &removed); err != nil {
		t.Fatalf("read old: %v", err)
	}
	if isPrimary || status != "offline" || removed == nil {
		t.Fatalf("old not retired: primary=%v status=%q removed=%v", isPrimary, status, removed)
	}
	// Old has no active sensor credential; new has exactly one.
	var oldActive, newActive int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id='old' AND scope=? AND revoked=0`, auth.ScopeSensor).Scan(&oldActive); err != nil {
		t.Fatalf("count old active credentials: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE sensor_id='new' AND scope=? AND revoked=0`, auth.ScopeSensor).Scan(&newActive); err != nil {
		t.Fatalf("count new active credentials: %v", err)
	}
	if oldActive != 0 {
		t.Fatalf("old active sensor credentials = %d, want 0", oldActive)
	}
	if newActive != 1 {
		t.Fatalf("new active sensor credentials = %d, want 1", newActive)
	}
	// Audit: a 'removed' lifecycle event carrying the replacement link.
	var eventType, details string
	if err := db.QueryRow(`SELECT event_type, details FROM sensor_lifecycle_events WHERE sensor_id='old' ORDER BY created_at DESC LIMIT 1`).Scan(&eventType, &details); err != nil {
		t.Fatalf("read lifecycle: %v", err)
	}
	if eventType != "removed" || !strings.Contains(details, `"replaced_by":"new"`) {
		t.Fatalf("audit event = %q details=%q", eventType, details)
	}
	// SensorExists stays true for the retired identity (tombstone invariant).
	if ok, _ := db.SensorExists("old"); !ok {
		t.Fatal("retired sensor identity must still exist")
	}
}

func TestReplacePrimarySensor_LifecycleDetailsAreValidJSON(t *testing.T) {
	db := newReplaceDB(t)
	now := time.Now().UTC()
	replacementID := "new\x00sensor"
	provisionSensor(t, db, "old", "old-host")
	provisionSensor(t, db, replacementID, "new-host")
	if err := db.SetPrimarySensor("old"); err != nil {
		t.Fatalf("set primary old: %v", err)
	}
	setLastSeen(t, db, "old", now.Add(-30*time.Minute))
	setLastSeen(t, db, replacementID, now)

	if _, _, err := db.ReplacePrimarySensor("old", replacementID, "admin-1", "redeploy", false); err != nil {
		t.Fatalf("replace: %v", err)
	}
	var details string
	if err := db.QueryRow(`SELECT details FROM sensor_lifecycle_events WHERE sensor_id='old' ORDER BY created_at DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatalf("read lifecycle details: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(details), &decoded); err != nil {
		t.Fatalf("lifecycle details are not valid JSON: %q: %v", details, err)
	}
	if decoded["replaced_by"] != replacementID {
		t.Fatalf("replaced_by = %q, want %q", decoded["replaced_by"], replacementID)
	}
}

func TestReplacePrimarySensor_Guards(t *testing.T) {
	t.Run("same sensor", func(t *testing.T) {
		db := newReplaceDB(t)
		provisionSensor(t, db, "x", "h")
		if _, _, err := db.ReplacePrimarySensor("x", "x", "a", "", false); !errors.Is(err, ErrReplaceSameSensor) {
			t.Fatalf("got %v, want ErrReplaceSameSensor", err)
		}
	})

	t.Run("replacement without credential", func(t *testing.T) {
		db := newReplaceDB(t)
		provisionSensor(t, db, "old", "h")
		if err := db.SetPrimarySensor("old"); err != nil {
			t.Fatal(err)
		}
		// "bare" has a sensor row but no credential.
		if err := db.RegisterSensor(models.Sensor{SensorID: "bare", Hostname: "h", CIDR: "192.0.2.0/24", Version: "t"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.ReplacePrimarySensor("old", "bare", "a", "", false); !errors.Is(err, ErrReplacementNoCredential) {
			t.Fatalf("got %v, want ErrReplacementNoCredential", err)
		}
		if n := activePrimaryCount(t, db); n != 1 {
			t.Fatalf("failed replace changed primary count: %d", n)
		}
	})

	t.Run("replacement stale unless forced", func(t *testing.T) {
		db := newReplaceDB(t)
		now := time.Now().UTC()
		provisionSensor(t, db, "old", "h")
		provisionSensor(t, db, "new", "h")
		if err := db.SetPrimarySensor("old"); err != nil {
			t.Fatal(err)
		}
		setLastSeen(t, db, "old", now.Add(-30*time.Minute))
		setLastSeen(t, db, "new", now.Add(-30*time.Minute)) // replacement also stale
		if _, _, err := db.ReplacePrimarySensor("old", "new", "a", "", false); !errors.Is(err, ErrReplacementStale) {
			t.Fatalf("got %v, want ErrReplacementStale", err)
		}
		if _, _, err := db.ReplacePrimarySensor("old", "new", "a", "", true); err != nil {
			t.Fatalf("force replace failed: %v", err)
		}
	})

	t.Run("recovered old primary is never force-overridable", func(t *testing.T) {
		db := newReplaceDB(t)
		now := time.Now().UTC()
		provisionSensor(t, db, "old", "h")
		provisionSensor(t, db, "new", "h")
		if err := db.SetPrimarySensor("old"); err != nil {
			t.Fatal(err)
		}
		setLastSeen(t, db, "old", now) // old is online again
		setLastSeen(t, db, "new", now)
		if _, _, err := db.ReplacePrimarySensor("old", "new", "a", "", false); !errors.Is(err, ErrOldPrimaryRecovered) {
			t.Fatalf("got %v, want ErrOldPrimaryRecovered", err)
		}
		// force overrides only the replacement-online guard, NOT the recovered
		// primary guard — a live primary must never be force-tombstoned.
		if _, _, err := db.ReplacePrimarySensor("old", "new", "a", "", true); !errors.Is(err, ErrOldPrimaryRecovered) {
			t.Fatalf("force must not retire a recovered primary: got %v, want ErrOldPrimaryRecovered", err)
		}
		if n := activePrimaryCount(t, db); n != 1 {
			t.Fatalf("refused replace changed primary count: %d", n)
		}
	})

	t.Run("pinned mismatch when expected old is not the primary", func(t *testing.T) {
		db := newReplaceDB(t)
		now := time.Now().UTC()
		provisionSensor(t, db, "primary", "h")
		provisionSensor(t, db, "other", "h")
		provisionSensor(t, db, "new", "h")
		if err := db.SetPrimarySensor("primary"); err != nil {
			t.Fatal(err)
		}
		setLastSeen(t, db, "new", now)
		// Operator thinks "other" is the primary, but "primary" is.
		if _, _, err := db.ReplacePrimarySensor("other", "new", "a", "", true); !errors.Is(err, ErrReplacePrimaryMismatch) {
			t.Fatalf("got %v, want ErrReplacePrimaryMismatch", err)
		}
		// The real primary and the healthy "other" are untouched.
		if n := activePrimaryCount(t, db); n != 1 {
			t.Fatalf("mismatch changed primary count: %d", n)
		}
		if ok, _ := db.SensorActive("other"); !ok {
			t.Fatal("wrong-victim: healthy sensor was tombstoned")
		}
	})
}
