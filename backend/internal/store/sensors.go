package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// execQuerier is satisfied by both *DB (via the embedded *sql.DB) and *sql.Tx,
// so sensor upsert logic can run either standalone or inside a transaction
// (e.g. ProvisionSensorToken's atomic revoke+upsert+mint).
type execQuerier interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// SensorOnlineWindow is how recently a sensor must have reported to count as
// "online". The sensor heartbeat is 30s, so 2 minutes tolerates several missed
// beats. It is the single source of truth for sensor liveness — the detection-
// health card (api/findings.go) shares it — so the dashboard and API never
// disagree on whether a sensor is live.
const SensorOnlineWindow = 2 * time.Minute

// EffectiveSensorStatus derives a sensor's true liveness from its last_seen, since
// the stored status column is only ever written 'online' (on report) or 'offline'
// (on removal) and never decays by elapsed time. A never-reporting or long-silent
// sensor is "offline"; anything within the online window is "online".
func EffectiveSensorStatus(lastSeen, now time.Time) string {
	// A future last_seen (clock skew) yields a negative delta and reads as online,
	// which is the safe interpretation of "just reported".
	if !lastSeen.IsZero() && now.Sub(lastSeen) <= SensorOnlineWindow {
		return "online"
	}
	return "offline"
}

// RegisterSensor creates or updates a sensor record (upsert).
// If this is the first sensor ever registered, it becomes the primary.
func (db *DB) RegisterSensor(sensor models.Sensor) error {
	return registerSensorOn(db, sensor, true, false)
}

// SensorExists reports whether a sensor row exists for this id, REGARDLESS of
// whether it currently has an active token. This is the identity check that
// governs new-vs-reset enrollment: a generic code may enroll only a never-seen
// id, while any existing id — active OR revoked — requires an admin-minted bound
// reset code, so an admin revocation cannot be silently undone by a generic code
// (beta-gate B1a).
func (db *DB) SensorExists(sensorID string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id = ?`, sensorID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// SensorActive reports whether a retained sensor identity is currently active.
// It deliberately distinguishes a never-seen identity from a tombstone at the
// call sites that need that distinction; both return false here.
func (db *DB) SensorActive(sensorID string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE sensor_id = ? AND removed_at IS NULL`, sensorID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// registerSensorOn writes the sensor row (and primary-promotion) against any
// execQuerier, so it composes into a larger transaction without duplicating SQL.
// When upsert is true an existing row is updated; when false a plain INSERT is
// used so a pre-existing identity causes a primary-key conflict — that is how a
// NEW enrollment atomically refuses to overwrite/reactivate an existing sensor.
func registerSensorOn(q execQuerier, sensor models.Sensor, upsert, reactivate bool) error {
	now := time.Now().UTC()

	// Auto-promote to primary if: no sensors exist yet, or no primary is set, or flag requested
	var count int
	if err := q.QueryRow(`SELECT COUNT(*) FROM sensors WHERE removed_at IS NULL`).Scan(&count); err != nil {
		return err
	}
	var primaryCount int
	if err := q.QueryRow(`SELECT COUNT(*) FROM sensors WHERE is_primary = TRUE AND removed_at IS NULL`).Scan(&primaryCount); err != nil {
		return err
	}
	makePrimary := count == 0 || primaryCount == 0 || sensor.IsPrimary

	insertSQL := `
		INSERT INTO sensors (sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)`
	if upsert {
		insertSQL += `
		ON CONFLICT(sensor_id) DO UPDATE SET
			hostname = excluded.hostname,
			os = excluded.os,
			arch = excluded.arch,
			cidr = excluded.cidr,
			version = excluded.version,
			last_seen = excluded.last_seen,
			status = 'online',
			interfaces = excluded.interfaces`
		if reactivate {
			insertSQL += `,
			removed_at = NULL,
			removed_by_token_id = NULL,
			removal_reason = ''`
		} else {
			// Ordinary registration may update an active identity, but it may not
			// resurrect a tombstone. Reactivation is reserved for an authenticated
			// reset in ProvisionSensorTokenWithActor.
			insertSQL += ` WHERE sensors.removed_at IS NULL`
		}
	}

	result, err := q.Exec(insertSQL, sensor.SensorID, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version, now, now, makePrimary, sensor.Interfaces)
	if err != nil {
		return err
	}
	if upsert && !reactivate {
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return ErrSensorRemoved
		}
	}

	// If this sensor should be primary, promote it and demote all other active
	// sensors in one statement. The conflict-update path intentionally does not
	// copy excluded.is_primary, so this explicit promotion is required when a
	// reset reactivates an existing non-primary identity with --primary.
	if makePrimary {
		if _, err := q.Exec(`
			UPDATE sensors
			SET is_primary = CASE WHEN sensor_id = ? THEN TRUE ELSE FALSE END
			WHERE removed_at IS NULL
		`, sensor.SensorID); err != nil {
			return err
		}
	}

	return nil
}

// RefreshSensorWithActiveToken updates metadata only when both the sensor row
// and the exact sensor credential are still active. The conditional UPDATE is
// the transaction's first write, so it serializes cleanly against removal: a
// request authenticated just before an admin removal cannot resurrect the row.
func (db *DB) RefreshSensorWithActiveToken(sensor models.Sensor, tokenID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.Exec(`
		UPDATE sensors
		SET hostname = ?, os = ?, arch = ?, cidr = ?, version = ?,
			last_seen = ?, status = 'online', interfaces = ?
		WHERE sensor_id = ? AND removed_at IS NULL
		  AND EXISTS (
			SELECT 1 FROM api_tokens
			WHERE token_id = ? AND sensor_id = ? AND scope = ? AND revoked = 0
		  )
	`, sensor.Hostname, sensor.OS, sensor.Arch, sensor.CIDR, sensor.Version,
		now, sensor.Interfaces, sensor.SensorID, tokenID, sensor.SensorID, auth.ScopeSensor)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var removed sql.NullTime
		if err := tx.QueryRow(`SELECT removed_at FROM sensors WHERE sensor_id = ?`, sensor.SensorID).Scan(&removed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSensorNotFound
			}
			return err
		}
		if removed.Valid {
			return ErrSensorRemoved
		}
		return ErrSensorTokenInactive
	}

	// Preserve the sensor's --primary contract and repair a legacy/corrupt fleet
	// with no active primary. The credential-checked UPDATE above is the
	// transaction's first write, so no removal or competing promotion can slip
	// between this decision and the single-statement election.
	promote := sensor.IsPrimary
	if !promote {
		var primaryCount int
		if err := tx.QueryRow(`
			SELECT COUNT(*) FROM sensors
			WHERE removed_at IS NULL AND is_primary = TRUE
		`).Scan(&primaryCount); err != nil {
			return err
		}
		promote = primaryCount == 0
	}
	if promote {
		if _, err := tx.Exec(`
			UPDATE sensors
			SET is_primary = CASE WHEN sensor_id = ? THEN TRUE ELSE FALSE END
			WHERE removed_at IS NULL
		`, sensor.SensorID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TouchSensor updates the last_seen timestamp for a sensor.
func (db *DB) TouchSensor(sensorID string) error {
	_, err := db.Exec(`UPDATE sensors SET last_seen = ?, status = 'online' WHERE sensor_id = ? AND removed_at IS NULL`,
		time.Now().UTC(), sensorID)
	return err
}

// ListSensors returns all registered sensors, primary first, then by last_seen.
func (db *DB) ListSensors() ([]models.Sensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors WHERE removed_at IS NULL
		ORDER BY is_primary DESC, last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	var sensors []models.Sensor
	for rows.Next() {
		var s models.Sensor
		if err := rows.Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary, &s.Interfaces); err != nil {
			return nil, err
		}
		s.Status = EffectiveSensorStatus(s.LastSeen, now)
		sensors = append(sensors, s)
	}

	return sensors, rows.Err()
}

// ListRemovedSensors returns retained sensor tombstones newest-first. It
// intentionally exposes only operator-safe lifecycle state; actor token IDs and
// raw audit details stay in the database.
func (db *DB) ListRemovedSensors() ([]models.RemovedSensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version,
			first_seen, last_seen, status, is_primary, interfaces,
			removed_at, removal_reason
		FROM sensors
		WHERE removed_at IS NOT NULL
		ORDER BY removed_at DESC, sensor_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sensors []models.RemovedSensor
	for rows.Next() {
		var s models.RemovedSensor
		if err := rows.Scan(
			&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version,
			&s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary, &s.Interfaces,
			&s.RemovedAt, &s.RemovalReason,
		); err != nil {
			return nil, err
		}
		sensors = append(sensors, s)
	}
	return sensors, rows.Err()
}

// ListSensorPartitions returns the active and removed dashboard partitions from
// one SQLite statement, so a concurrent removal/reactivation cannot make one
// response contain the same sensor in both arrays (or neither).
func (db *DB) ListSensorPartitions() ([]models.Sensor, []models.RemovedSensor, error) {
	rows, err := db.Query(`
		SELECT sensor_id, hostname, os, arch, cidr, version,
			first_seen, last_seen, status, is_primary, interfaces,
			removed_at, removal_reason
		FROM sensors
		ORDER BY
			CASE WHEN removed_at IS NULL THEN 0 ELSE 1 END,
			is_primary DESC,
			CASE WHEN removed_at IS NULL THEN last_seen END DESC,
			removed_at DESC,
			sensor_id ASC
	`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	var active []models.Sensor
	var removed []models.RemovedSensor
	for rows.Next() {
		var sensor models.Sensor
		var removedAt sql.NullTime
		var removalReason string
		if err := rows.Scan(
			&sensor.SensorID, &sensor.Hostname, &sensor.OS, &sensor.Arch, &sensor.CIDR, &sensor.Version,
			&sensor.FirstSeen, &sensor.LastSeen, &sensor.Status, &sensor.IsPrimary, &sensor.Interfaces,
			&removedAt, &removalReason,
		); err != nil {
			return nil, nil, err
		}
		if removedAt.Valid {
			// Tombstoned rows keep their stored 'offline' (set by RemoveSensor /
			// ReplacePrimarySensor); only active rows get live-derived status.
			removed = append(removed, models.RemovedSensor{
				Sensor:        sensor,
				RemovedAt:     removedAt.Time.UTC(),
				RemovalReason: removalReason,
			})
		} else {
			sensor.Status = EffectiveSensorStatus(sensor.LastSeen, now)
			active = append(active, sensor)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return active, removed, nil
}

// GetPrimarySensor returns the sensor marked as primary, or nil if none.
func (db *DB) GetPrimarySensor() (*models.Sensor, error) {
	var s models.Sensor
	err := db.QueryRow(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors WHERE is_primary = TRUE AND removed_at IS NULL LIMIT 1
	`).Scan(&s.SensorID, &s.Hostname, &s.OS, &s.Arch, &s.CIDR, &s.Version, &s.FirstSeen, &s.LastSeen, &s.Status, &s.IsPrimary, &s.Interfaces)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// SetPrimarySensor makes the given sensor primary and demotes all others.
func (db *DB) SetPrimarySensor(sensorID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Promote the active target first. This is the transaction's first write and
	// therefore orders promotion against a concurrent removal.
	result, err := tx.Exec(`UPDATE sensors SET is_primary = TRUE WHERE sensor_id = ? AND removed_at IS NULL`, sensorID)
	if err != nil {
		tx.Rollback()
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		tx.Rollback()
		return ErrSensorNotFound
	}

	// The target is known active and the write lock is held; demote other active
	// sensors without changing retained tombstones.
	if _, err := tx.Exec(`UPDATE sensors SET is_primary = FALSE WHERE sensor_id != ? AND removed_at IS NULL`, sensorID); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// ErrLastPrimarySensor is retained for API compatibility. Any current primary
// must be replaced before removal, which guarantees the active fleet never has
// a zero-primary transition.
var ErrLastPrimarySensor = errors.New("cannot remove the primary sensor")

// ErrSensorRemoved protects the identity tombstone from ordinary registration.
var ErrSensorRemoved = errors.New("sensor identity has been removed")

// ErrSensorTokenInactive means an identity is active but the credential used
// for a metadata refresh no longer is.
var ErrSensorTokenInactive = errors.New("sensor token is no longer active")

// Replace-primary sentinel errors (beta sensor-redeploy UX).
var (
	// ErrReplaceSameSensor: the replacement and the old primary are the same id.
	ErrReplaceSameSensor = errors.New("a sensor cannot replace itself")
	// ErrReplacementNoCredential: the replacement is active but holds no live
	// sensor credential, so promoting it would leave a primary that cannot report.
	ErrReplacementNoCredential = errors.New("replacement sensor has no active credential")
	// ErrReplacementStale: the replacement is not currently online (override: force).
	ErrReplacementStale = errors.New("replacement sensor is not currently online")
	// ErrOldPrimaryRecovered: the primary being replaced has resumed reporting
	// since the operator reviewed it (override: force).
	ErrOldPrimaryRecovered = errors.New("primary sensor has resumed reporting")
	// ErrReplacePrimaryMismatch: the reviewed primary is no longer the current
	// active primary (it moved or was removed under us), so nothing was replaced.
	ErrReplacePrimaryMismatch = errors.New("expected primary is no longer the current primary")
)

// RemoveSensor tombstones a non-primary sensor, revokes only sensor-scoped
// credentials, and records an audit event in one transaction. It never deletes
// the identity row or historical token rows: SensorExists must stay true forever
// so a generic enrollment code cannot reclaim a removed identity. Repeating the
// removal is idempotent and returns the original timestamp.
func (db *DB) RemoveSensor(sensorID, actorTokenID, reason string) (time.Time, error) {
	tx, err := db.Begin()
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.Exec(`
		UPDATE sensors
		SET removed_at = ?, removed_by_token_id = ?, removal_reason = ?, status = 'offline'
		WHERE sensor_id = ? AND removed_at IS NULL AND is_primary = FALSE
	`, now, actorTokenID, reason, sensorID)
	if err != nil {
		return time.Time{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return time.Time{}, err
	}
	if rows == 0 {
		var isPrimary bool
		var removed sql.NullTime
		if err := tx.QueryRow(`SELECT is_primary, removed_at FROM sensors WHERE sensor_id = ?`, sensorID).Scan(&isPrimary, &removed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return time.Time{}, ErrSensorNotFound
			}
			return time.Time{}, err
		}
		if removed.Valid {
			return removed.Time.UTC(), nil
		}
		if isPrimary {
			return time.Time{}, ErrLastPrimarySensor
		}
		return time.Time{}, fmt.Errorf("sensor removal made no change")
	}

	if _, err := tx.Exec(`
		UPDATE api_tokens SET revoked = 1
		WHERE sensor_id = ? AND scope = ? AND revoked = 0
	`, sensorID, auth.ScopeSensor); err != nil {
		return time.Time{}, err
	}
	if err := insertSensorLifecycleOn(tx, sensorID, "removed", actorTokenID, reason, now); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

// ReplacePrimarySensor atomically retires a (typically stale) primary sensor by
// promoting a healthy replacement in its place: it promotes the replacement to
// primary AND tombstones+revokes the old primary in one transaction. This removes
// the redeploy trap where a new sensor registers as non-primary and the old, dead
// primary cannot be removed (a primary is never directly removable).
//
// The old primary is PINNED by the exact id the operator reviewed and asserted via
// RowsAffected, never derived from is_primary=TRUE alone — so a concurrent
// re-election (RefreshSensorWithActiveToken promotes on --primary) can never make
// this tombstone+revoke the wrong, healthy sensor. Write ordering (promote first)
// takes SQLite's single writer lock before the guard reads and guarantees the
// active fleet never transitions through zero primary. force overrides ONLY the
// replacement-not-online guard; the old-primary-recovered guard is never
// overridable, so a recovered primary can never be force-tombstoned mid-collection.
//
// Guards, in order: same-id (ErrReplaceSameSensor); replacement must be active,
// non-removed, and hold a live sensor credential (ErrSensorNotFound /
// ErrSensorRemoved / ErrReplacementNoCredential); replacement online unless force
// (ErrReplacementStale); old must not have resumed reporting (ErrOldPrimaryRecovered,
// not force-overridable); old still the exact current active primary
// (ErrReplacePrimaryMismatch).
func (db *DB) ReplacePrimarySensor(expectedOldPrimaryID, replacementID, actorTokenID, reason string, force bool) (models.Sensor, time.Time, error) {
	expectedOldPrimaryID = strings.TrimSpace(expectedOldPrimaryID)
	replacementID = strings.TrimSpace(replacementID)
	if expectedOldPrimaryID == "" || replacementID == "" {
		return models.Sensor{}, time.Time{}, ErrSensorNotFound
	}
	if expectedOldPrimaryID == replacementID {
		return models.Sensor{}, time.Time{}, ErrReplaceSameSensor
	}
	if strings.TrimSpace(reason) == "" {
		reason = "replaced primary " + expectedOldPrimaryID
	}

	tx, err := db.Begin()
	if err != nil {
		return models.Sensor{}, time.Time{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()

	// S1: promote the replacement. First write -> takes the writer lock before the
	// guard reads. Requires it be active, non-removed, and hold a live credential so
	// the new primary can actually report.
	res, err := tx.Exec(`
		UPDATE sensors SET is_primary = TRUE
		WHERE sensor_id = ? AND removed_at IS NULL
		  AND EXISTS (SELECT 1 FROM api_tokens WHERE sensor_id = ? AND scope = ? AND revoked = 0)
	`, replacementID, replacementID, auth.ScopeSensor)
	if err != nil {
		return models.Sensor{}, time.Time{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var removedAt sql.NullTime
		switch err := tx.QueryRow(`SELECT removed_at FROM sensors WHERE sensor_id = ?`, replacementID).Scan(&removedAt); {
		case errors.Is(err, sql.ErrNoRows):
			return models.Sensor{}, time.Time{}, ErrSensorNotFound
		case err != nil:
			return models.Sensor{}, time.Time{}, err
		case removedAt.Valid:
			return models.Sensor{}, time.Time{}, ErrSensorRemoved
		default:
			return models.Sensor{}, time.Time{}, ErrReplacementNoCredential
		}
	}

	// S2: replacement must be online (unless forced) so we don't retire the current
	// primary in favor of a sensor that is itself dead.
	if !force {
		var repLastSeen time.Time
		if err := tx.QueryRow(`SELECT last_seen FROM sensors WHERE sensor_id = ?`, replacementID).Scan(&repLastSeen); err != nil {
			return models.Sensor{}, time.Time{}, err
		}
		if EffectiveSensorStatus(repLastSeen, now) != "online" {
			return models.Sensor{}, time.Time{}, ErrReplacementStale
		}
	}

	// S2b: never retire a primary that is reporting again. If it has resumed since
	// the operator viewed it, refuse. This guard is deliberately NOT force-overridable
	// (force only overrides the replacement-not-online check): a live, actively
	// collecting primary must be retired through the ordinary make-primary + remove
	// flow, never force-tombstoned out from under live data collection — otherwise a
	// human-timed "promote anyway" retry could silently kill a recovered primary.
	// Scoped to the ACTUAL current primary: if the reviewed id is not the active
	// primary, skip here and let S3 return the more precise mismatch error.
	{
		var oldLastSeen time.Time
		switch err := tx.QueryRow(`SELECT last_seen FROM sensors WHERE sensor_id = ? AND is_primary = TRUE AND removed_at IS NULL`, expectedOldPrimaryID).Scan(&oldLastSeen); {
		case err == nil:
			if EffectiveSensorStatus(oldLastSeen, now) == "online" {
				return models.Sensor{}, time.Time{}, ErrOldPrimaryRecovered
			}
		case errors.Is(err, sql.ErrNoRows):
			// not the current active primary; S3 asserts and returns mismatch
		default:
			return models.Sensor{}, time.Time{}, err
		}
	}

	// S3: tombstone + demote the OLD primary, pinned to the reviewed id and asserted
	// to still be the current active primary. rows==0 means it moved/was removed.
	res, err = tx.Exec(`
		UPDATE sensors
		SET is_primary = FALSE, removed_at = ?, removed_by_token_id = ?, removal_reason = ?, status = 'offline'
		WHERE sensor_id = ? AND is_primary = TRUE AND removed_at IS NULL
	`, now, actorTokenID, reason, expectedOldPrimaryID)
	if err != nil {
		return models.Sensor{}, time.Time{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return models.Sensor{}, time.Time{}, ErrReplacePrimaryMismatch
	}

	// S4: heal any stray extra active primaries (a corrupt >1-primary fleet). Cannot
	// touch the replacement (excluded) and cannot reach zero (replacement stays TRUE).
	if _, err := tx.Exec(`
		UPDATE sensors SET is_primary = FALSE
		WHERE sensor_id != ? AND removed_at IS NULL AND is_primary = TRUE
	`, replacementID); err != nil {
		return models.Sensor{}, time.Time{}, err
	}

	// S5: revoke ONLY the old primary's sensor-scoped credential.
	if _, err := tx.Exec(`
		UPDATE api_tokens SET revoked = 1
		WHERE sensor_id = ? AND scope = ? AND revoked = 0
	`, expectedOldPrimaryID, auth.ScopeSensor); err != nil {
		return models.Sensor{}, time.Time{}, err
	}

	// S6: audit. event_type 'removed' satisfies the schema CHECK; details records the
	// replacement so a replace is distinguishable from a plain operator removal.
	details := fmt.Sprintf(`{"replaced_by":%q}`, replacementID)
	if err := insertSensorLifecycleWithDetailsOn(tx, expectedOldPrimaryID, "removed", actorTokenID, reason, details, now); err != nil {
		return models.Sensor{}, time.Time{}, err
	}

	// S7: read back the new primary for the response.
	var newPrimary models.Sensor
	if err := tx.QueryRow(`
		SELECT sensor_id, hostname, os, arch, cidr, version, first_seen, last_seen, status, is_primary, interfaces
		FROM sensors WHERE sensor_id = ?
	`, replacementID).Scan(&newPrimary.SensorID, &newPrimary.Hostname, &newPrimary.OS, &newPrimary.Arch, &newPrimary.CIDR,
		&newPrimary.Version, &newPrimary.FirstSeen, &newPrimary.LastSeen, &newPrimary.Status, &newPrimary.IsPrimary, &newPrimary.Interfaces); err != nil {
		return models.Sensor{}, time.Time{}, err
	}
	newPrimary.Status = EffectiveSensorStatus(newPrimary.LastSeen, now)

	if err := tx.Commit(); err != nil {
		return models.Sensor{}, time.Time{}, err
	}
	return newPrimary, now, nil
}

func insertSensorLifecycleOn(q execQuerier, sensorID, eventType, actor, reason string, at time.Time) error {
	return insertSensorLifecycleWithDetailsOn(q, sensorID, eventType, actor, reason, "{}", at)
}

// insertSensorLifecycleWithDetailsOn records a lifecycle event with a JSON details
// blob (e.g. {"replaced_by":"<id>"} to distinguish a replace from a plain removal;
// event_type stays within the schema CHECK of 'removed'|'reactivated').
func insertSensorLifecycleWithDetailsOn(q execQuerier, sensorID, eventType, actor, reason, details string, at time.Time) error {
	if strings.TrimSpace(details) == "" {
		details = "{}"
	}
	_, err := q.Exec(`
		INSERT INTO sensor_lifecycle_events
			(event_id, sensor_id, event_type, actor, reason, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, uuid.NewString(), sensorID, eventType, actor, reason, details, at.UTC())
	return err
}
