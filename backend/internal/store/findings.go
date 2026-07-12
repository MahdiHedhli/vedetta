package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

const findingRecurrenceWindow = 7 * 24 * time.Hour
const findingEvidenceSummaryCap = 100

var (
	ErrFindingNotFound          = errors.New("finding not found")
	ErrInvalidFindingStatus     = errors.New("invalid finding status")
	ErrResolutionReasonRequired = errors.New("resolution reason is required")
)

// ProcessedEventRecord is the transaction boundary between the unified
// processor and SQLite. Identity is carried separately so adapters cannot
// accidentally turn a caller-controlled Event field into an authoritative
// association.
type ProcessedEventRecord struct {
	Event              models.Event
	DeviceID           string
	IdentityConfidence float64
	IdentityReason     string
	IdentityEvidence   json.RawMessage
	Origin             string
	SensorID           string
	Disposition        models.FindingDisposition
	SuppressionRuleID  string
	Evidence           []models.DetectionEvidence
	Findings           []models.FindingCandidate
}

// PersistProcessedResult describes one all-or-nothing event transaction.
type PersistProcessedResult struct {
	EventID    string
	FindingIDs []string
	Inserted   bool
	Duplicate  bool
}

// ProcessedEventExists is the processor's early replay gate. The definitive
// uniqueness guarantee remains the events primary key inside
// PersistProcessedEvent; this cheap lookup prevents a known replay from
// mutating in-memory behavioral detector state before reaching that constraint.
func (db *DB) ProcessedEventExists(ctx context.Context, eventID string) (bool, error) {
	if strings.TrimSpace(eventID) == "" {
		return false, nil
	}
	var marker int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM events WHERE event_id = ? LIMIT 1`, eventID).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check processed event: %w", err)
	}
	return true, nil
}

// PersistProcessedEvent atomically inserts an immutable event, all typed
// detector evidence, and every finding relationship/update. Duplicate event
// IDs are successful no-ops and never increment a finding occurrence count.
func (db *DB) PersistProcessedEvent(ctx context.Context, record ProcessedEventRecord) (PersistProcessedResult, error) {
	result := PersistProcessedResult{EventID: record.Event.EventID, FindingIDs: []string{}}
	if strings.TrimSpace(record.Event.EventID) == "" {
		return result, errors.New("event_id is required")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin processed event: %w", err)
	}
	defer tx.Rollback()

	inserted, err := insertProcessedEvent(ctx, tx, record)
	if err != nil {
		return result, err
	}
	if !inserted {
		// A duplicate must not mutate evidence or finding aggregates. Commit the
		// read/no-op transaction so callers receive a normal duplicate result.
		if err := tx.Commit(); err != nil {
			return result, fmt.Errorf("commit duplicate event: %w", err)
		}
		result.Duplicate = true
		return result, nil
	}

	for i := range record.Evidence {
		evidence := record.Evidence[i]
		if evidence.EvidenceID == "" {
			evidence.EvidenceID = uuid.NewString()
		}
		evidence.EventID = record.Event.EventID
		if evidence.CreatedAt.IsZero() {
			evidence.CreatedAt = time.Now().UTC()
		}
		if err := insertDetectionEvidence(ctx, tx, evidence); err != nil {
			return result, err
		}
	}

	seenFindingKeys := make(map[string]struct{}, len(record.Findings))
	for _, candidate := range record.Findings {
		if candidate.FindingKey == "" {
			continue
		}
		// Defensive de-duplication keeps occurrence_count event-based even if a
		// detector emitted equivalent evidence twice for one event.
		if _, seen := seenFindingKeys[candidate.FindingKey]; seen {
			continue
		}
		seenFindingKeys[candidate.FindingKey] = struct{}{}

		findingID, err := upsertFinding(ctx, tx, record.Event.EventID, candidate)
		if err != nil {
			return result, err
		}
		if findingID != "" {
			result.FindingIDs = append(result.FindingIDs, findingID)
			for _, evidenceID := range candidate.EvidenceIDs {
				if err := linkFindingEvidence(ctx, tx, findingID, evidenceID); err != nil {
					return result, err
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit processed event: %w", err)
	}
	result.Inserted = true
	return result, nil
}

// SourceHash derives a stable Core-local pseudonym from a raw source address.
// It reuses the private, randomly generated asset-identity key, domain-separated
// as "source_ip". The key never leaves the local database.
func (db *DB) SourceHash(ctx context.Context, sourceIP string) (string, error) {
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return "", nil
	}
	if parsed := net.ParseIP(sourceIP); parsed != nil {
		sourceIP = parsed.String()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key, err := db.identityHMACKeyCached()
	if err != nil {
		return "", err
	}
	hash := identityValueHMAC(key, "source_ip", sourceIP)
	return hash, nil
}

func insertProcessedEvent(ctx context.Context, tx *sql.Tx, record ProcessedEventRecord) (bool, error) {
	e := record.Event
	tagsJSON, err := json.Marshal(e.Tags)
	if err != nil {
		return false, fmt.Errorf("marshal event tags: %w", err)
	}
	if len(e.Tags) == 0 {
		tagsJSON = []byte("[]")
	}
	metadata := e.Metadata
	if metadata == "" {
		metadata = "{}"
	}
	identityEvidence := string(record.IdentityEvidence)
	if identityEvidence == "" {
		identityEvidence = "{}"
	}
	segment := e.NetworkSegment
	if segment == "" {
		segment = "default"
	}
	disposition := record.Disposition
	if disposition == "" {
		disposition = models.DispositionActive
	}
	now := time.Now().UTC()
	timestamp := clampFutureEventTimestamp(e.Timestamp, now).UTC()
	if e.Timestamp.IsZero() {
		timestamp = now
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO events
			(event_id, timestamp, event_type, source_hash, source_ip, server_ip, domain, query_type,
			 resolved_ip, blocked, outcome, anomaly_score, tags, geo, device_vendor, network_segment,
			 dns_source, threat_desc, metadata, matched_indicator, match_type,
			 device_id, identity_confidence, identity_reason, identity_evidence,
			 origin, sensor_id, disposition, suppression_rule_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(event_id) DO NOTHING`,
		e.EventID, timestamp, e.EventType, e.SourceHash,
		nullableString(e.SourceIP), nullableString(e.ServerIP), nullableString(e.Domain), nullableString(e.QueryType),
		nullableString(e.ResolvedIP), e.Blocked, persistedEventOutcome(e.Outcome, e.Blocked), e.AnomalyScore, string(tagsJSON), nullableString(e.Geo),
		nullableString(e.DeviceVendor), segment, nullableString(e.DNSSource), nullableString(e.ThreatDesc), metadata,
		nullableString(e.MatchedIndicator), nullableString(e.MatchType), nullableString(record.DeviceID),
		record.IdentityConfidence, record.IdentityReason, identityEvidence, record.Origin, nullableString(record.SensorID),
		string(disposition), record.SuppressionRuleID,
	)
	if err != nil {
		return false, fmt.Errorf("insert processed event: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("processed event rows affected: %w", err)
	}
	return rows == 1, nil
}

func insertDetectionEvidence(ctx context.Context, tx *sql.Tx, e models.DetectionEvidence) error {
	deviceContext := string(e.DeviceContext)
	if deviceContext == "" {
		deviceContext = "{}"
	}
	details := string(e.Details)
	if details == "" {
		details = "{}"
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO event_detection_evidence
			(evidence_id, event_id, detector, category, observable_type, observable_value,
			 threat_source, source_confidence, feed_freshness, feed_stale, rationale,
			 score_contribution, outcome, device_context, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.EvidenceID, e.EventID, e.Detector, e.Category, e.ObservableType, e.ObservableValue,
		e.ThreatSource, e.SourceConfidence, nullableTime(e.FeedFreshness), e.FeedStale,
		e.Rationale, e.ScoreContribution, e.Outcome, deviceContext, details, e.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert detection evidence: %w", err)
	}
	return nil
}

type latestFinding struct {
	ID         string
	Generation int
	Status     models.FindingStatus
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt *time.Time
	Evidence   string
}

func upsertFinding(ctx context.Context, tx *sql.Tx, eventID string, c models.FindingCandidate) (string, error) {
	when := c.ObservedAt.UTC()
	if when.IsZero() {
		when = time.Now().UTC()
	}
	if c.Priority == "" {
		c.Priority = priorityForScore(c.Score)
	}
	if c.Disposition == "" {
		c.Disposition = models.DispositionActive
	}

	latest, err := selectLatestFindingForCandidate(ctx, tx, c)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return insertFindingGeneration(ctx, tx, eventID, c, 1, "")
	}
	selectedID := latest.ID
	historicalGeneration := false
	if !latest.FirstSeen.IsZero() && when.Before(latest.FirstSeen) {
		if historical, histErr := selectHistoricalFindingForCandidate(ctx, tx, c, when); histErr == nil {
			// A generation begins logically after the prior resolved incident has
			// been quiet for the recurrence window, even when an out-of-order event
			// arrives before that generation's first event was originally ingested.
			// In that case attach to the following generation and move its first_seen
			// backward instead of corrupting the prior resolved incident.
			if historical.Status == models.FindingStatusResolved && historical.ResolvedAt != nil &&
				when.After(*historical.ResolvedAt) && when.Sub(historical.LastSeen) > findingRecurrenceWindow {
				if next, nextErr := selectNextFindingGeneration(ctx, tx, historical.ID); nextErr == nil {
					latest = next
				} else if !errors.Is(nextErr, sql.ErrNoRows) {
					return "", nextErr
				} else {
					latest = historical
				}
			} else {
				latest = historical
			}
			historicalGeneration = latest.ID != selectedID
		} else if !errors.Is(histErr, sql.ErrNoRows) {
			return "", histErr
		}
	}

	// Link first. If this event is already supporting this finding, it must not
	// change any aggregate even when called outside the event duplicate guard.
	linked, err := linkFindingEvent(ctx, tx, latest.ID, eventID, when)
	if err != nil {
		return "", err
	}
	if !linked {
		return latest.ID, nil
	}

	if latest.Status == models.FindingStatusResolved {
		if historicalGeneration {
			if err := updateResolvedFindingEvidence(ctx, tx, latest, eventID, c, when); err != nil {
				return "", err
			}
			return latest.ID, nil
		}
		// A delayed/out-of-order supporting event that predates the operator's
		// resolution is evidence for the resolved incident, not a recurrence.
		if latest.ResolvedAt != nil && !when.After(*latest.ResolvedAt) {
			if err := updateResolvedFindingEvidence(ctx, tx, latest, eventID, c, when); err != nil {
				return "", err
			}
			return latest.ID, nil
		}
		quiet := when.Sub(latest.LastSeen)
		if quiet < 0 {
			quiet = 0
		}
		if quiet <= findingRecurrenceWindow {
			if err := reopenFinding(ctx, tx, latest, eventID, c, when); err != nil {
				return "", err
			}
			return latest.ID, nil
		}

		// The link above belongs to the old generation only provisionally. Move it
		// to the new generation so one event is not counted by both incidents.
		if _, err := tx.ExecContext(ctx, `DELETE FROM finding_events WHERE finding_id = ? AND event_id = ?`, latest.ID, eventID); err != nil {
			return "", fmt.Errorf("unlink prior finding generation: %w", err)
		}
		return insertFindingGeneration(ctx, tx, eventID, c, latest.Generation+1, latest.ID)
	}

	mergedEvidence := mergeEvidenceIDs(latest.Evidence, c.EvidenceIDs)
	allowed, blocked, observed, outcome := findingOutcome(c.Outcome, c.Blocked)
	_, err = tx.ExecContext(ctx, `
		UPDATE findings SET
			first_seen = MIN(first_seen, ?),
			last_seen = MAX(last_seen, ?),
			occurrence_count = occurrence_count + 1,
			maximum_score = MAX(maximum_score, ?),
			current_priority = CASE WHEN maximum_score < ? THEN ? ELSE current_priority END,
			allowed_count = allowed_count + ?, blocked_count = blocked_count + ?, observed_count = observed_count + ?,
			outcome = CASE
				WHEN (((allowed_count + ?) > 0) + ((blocked_count + ?) > 0) + ((observed_count + ?) > 0)) > 1 THEN 'mixed'
				WHEN (blocked_count + ?) > 0 THEN 'blocked'
				WHEN (allowed_count + ?) > 0 THEN 'allowed' ELSE 'observed' END,
			reason = CASE WHEN ? >= maximum_score THEN ? ELSE reason END,
			recommended_action = CASE WHEN ? >= maximum_score THEN ? ELSE recommended_action END,
			last_event_id = CASE WHEN ? >= last_seen THEN ? ELSE last_event_id END,
			evidence = ?,
			disposition = CASE WHEN ? >= last_seen THEN ? ELSE disposition END,
			suppression_rule_id = CASE WHEN ? >= last_seen THEN ? ELSE suppression_rule_id END,
			updated_at = ?
		WHERE finding_id = ?`,
		when, when, c.Score, c.Score, string(c.Priority), allowed, blocked, observed,
		allowed, blocked, observed, blocked, allowed, c.Score, c.Reason, c.Score, c.RecommendedAction,
		when, eventID, mergedEvidence, when, string(c.Disposition), when, c.SuppressionRuleID,
		time.Now().UTC(), latest.ID,
	)
	if err != nil {
		return "", fmt.Errorf("update active finding: %w", err)
	}
	_ = outcome // outcome is expressed atomically in the SQL above.
	return latest.ID, nil
}

func selectHistoricalFindingForCandidate(ctx context.Context, tx *sql.Tx, c models.FindingCandidate, when time.Time) (latestFinding, error) {
	var query string
	var args []any
	if strings.TrimSpace(c.DeviceID) == "" {
		query = `SELECT finding_id, generation, status, first_seen, last_seen, resolved_at, COALESCE(evidence, '{}')
			FROM findings WHERE finding_key = ? AND first_seen <= ?
			ORDER BY first_seen DESC, generation DESC LIMIT 1`
		args = []any{c.FindingKey, when}
	} else {
		canonicalID, err := dbCanonicalDeviceIDTx(tx, c.DeviceID)
		if err != nil {
			return latestFinding{}, err
		}
		query = `WITH RECURSIVE family(device_id) AS (
				SELECT ? UNION SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
			)
			SELECT finding_id, generation, status, first_seen, last_seen, resolved_at, COALESCE(evidence, '{}')
			FROM findings WHERE device_id IN (SELECT device_id FROM family)
			  AND detector = ? AND primary_observable_type = ? AND primary_observable = ? AND first_seen <= ?
			ORDER BY first_seen DESC, generation DESC LIMIT 1`
		args = []any{canonicalID, c.Detector, c.PrimaryObservableType, c.PrimaryObservable, when}
	}
	var f latestFinding
	var resolvedAt sql.NullTime
	err := tx.QueryRowContext(ctx, query, args...).Scan(
		&f.ID, &f.Generation, &f.Status, &f.FirstSeen, &f.LastSeen, &resolvedAt, &f.Evidence)
	if err != nil {
		return f, err
	}
	if resolvedAt.Valid {
		resolved := resolvedAt.Time
		f.ResolvedAt = &resolved
	}
	return f, nil
}

func selectNextFindingGeneration(ctx context.Context, tx *sql.Tx, previousID string) (latestFinding, error) {
	var f latestFinding
	var resolvedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `
		SELECT finding_id, generation, status, first_seen, last_seen, resolved_at, COALESCE(evidence, '{}')
		FROM findings WHERE previous_finding_id = ? ORDER BY generation ASC LIMIT 1`, previousID).
		Scan(&f.ID, &f.Generation, &f.Status, &f.FirstSeen, &f.LastSeen, &resolvedAt, &f.Evidence)
	if err != nil {
		return f, err
	}
	if resolvedAt.Valid {
		resolved := resolvedAt.Time
		f.ResolvedAt = &resolved
	}
	return f, nil
}

func selectLatestFinding(ctx context.Context, tx *sql.Tx, key string) (latestFinding, error) {
	var f latestFinding
	var resolvedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `
			SELECT finding_id, generation, status, first_seen, last_seen, resolved_at, COALESCE(evidence, '{}')
			FROM findings WHERE finding_key = ? ORDER BY generation DESC LIMIT 1`, key).
		Scan(&f.ID, &f.Generation, &f.Status, &f.FirstSeen, &f.LastSeen, &resolvedAt, &f.Evidence)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return f, sql.ErrNoRows
		}
		return f, fmt.Errorf("select latest finding: %w", err)
	}
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
	return f, nil
}

// selectLatestFindingForCandidate treats all devices currently redirected to
// one canonical asset as the same finding identity. Raw finding.device_id and
// finding_key remain untouched so merge/split history stays auditable.
func selectLatestFindingForCandidate(ctx context.Context, tx *sql.Tx, c models.FindingCandidate) (latestFinding, error) {
	if strings.TrimSpace(c.DeviceID) == "" {
		return selectLatestFinding(ctx, tx, c.FindingKey)
	}
	canonicalID, err := dbCanonicalDeviceIDTx(tx, c.DeviceID)
	if err != nil {
		return latestFinding{}, err
	}
	var f latestFinding
	var resolvedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		WITH RECURSIVE family(device_id) AS (
			SELECT ?
			UNION
			SELECT d.device_id FROM devices d JOIN family f ON d.merged_into_device_id = f.device_id
		)
		SELECT finding_id, generation, status, first_seen, last_seen, resolved_at, COALESCE(evidence, '{}')
		FROM findings
		WHERE device_id IN (SELECT device_id FROM family)
		  AND detector = ? AND primary_observable_type = ? AND primary_observable = ?
		ORDER BY CASE WHEN status = 'resolved' THEN 1 ELSE 0 END, generation DESC, last_seen DESC
		LIMIT 1`, canonicalID, c.Detector, c.PrimaryObservableType, c.PrimaryObservable).
		Scan(&f.ID, &f.Generation, &f.Status, &f.FirstSeen, &f.LastSeen, &resolvedAt, &f.Evidence)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return latestFinding{}, sql.ErrNoRows
		}
		return latestFinding{}, fmt.Errorf("select canonical-family finding: %w", err)
	}
	if resolvedAt.Valid {
		resolved := resolvedAt.Time
		f.ResolvedAt = &resolved
	}
	return f, nil
}

// Small wrapper keeps the candidate lookup explicit without exposing DB on the
// helper signature; canonicalDeviceIDTx already enforces cycle/depth guards.
func dbCanonicalDeviceIDTx(tx *sql.Tx, deviceID string) (string, error) {
	deviceID = strings.TrimSpace(deviceID)
	seen := map[string]bool{}
	for hops := 0; deviceID != "" && hops < 32; hops++ {
		if seen[deviceID] {
			return "", fmt.Errorf("device merge redirect cycle at %s", deviceID)
		}
		seen[deviceID] = true
		var next sql.NullString
		if err := tx.QueryRow(`SELECT merged_into_device_id FROM devices WHERE device_id = ?`, deviceID).Scan(&next); err != nil {
			return "", err
		}
		if !next.Valid || strings.TrimSpace(next.String) == "" {
			return deviceID, nil
		}
		deviceID = next.String
	}
	return "", fmt.Errorf("device merge redirect depth exceeded")
}

func updateResolvedFindingEvidence(ctx context.Context, tx *sql.Tx, latest latestFinding, eventID string, c models.FindingCandidate, when time.Time) error {
	mergedEvidence := mergeEvidenceIDs(latest.Evidence, c.EvidenceIDs)
	allowed, blocked, observed, _ := findingOutcome(c.Outcome, c.Blocked)
	_, err := tx.ExecContext(ctx, `
		UPDATE findings SET
			first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?),
			occurrence_count = occurrence_count + 1,
			maximum_score = MAX(maximum_score, ?),
			current_priority = CASE WHEN maximum_score < ? THEN ? ELSE current_priority END,
			allowed_count = allowed_count + ?, blocked_count = blocked_count + ?, observed_count = observed_count + ?,
			outcome = CASE
				WHEN (((allowed_count + ?) > 0) + ((blocked_count + ?) > 0) + ((observed_count + ?) > 0)) > 1 THEN 'mixed'
				WHEN (blocked_count + ?) > 0 THEN 'blocked'
				WHEN (allowed_count + ?) > 0 THEN 'allowed' ELSE 'observed' END,
			reason = CASE WHEN ? >= maximum_score THEN ? ELSE reason END,
			recommended_action = CASE WHEN ? >= maximum_score THEN ? ELSE recommended_action END,
			last_event_id = CASE WHEN ? >= last_seen THEN ? ELSE last_event_id END,
			evidence = ?, updated_at = ?
		WHERE finding_id = ?`,
		when, when, c.Score, c.Score, string(c.Priority), allowed, blocked, observed,
		allowed, blocked, observed, blocked, allowed, c.Score, c.Reason, c.Score, c.RecommendedAction,
		when, eventID, mergedEvidence, time.Now().UTC(), latest.ID,
	)
	if err != nil {
		return fmt.Errorf("attach delayed evidence to resolved finding: %w", err)
	}
	return nil
}

func insertFindingGeneration(ctx context.Context, tx *sql.Tx, eventID string, c models.FindingCandidate, generation int, previousID string) (string, error) {
	id := uuid.NewString()
	now := time.Now().UTC()
	when := c.ObservedAt.UTC()
	if when.IsZero() {
		when = now
	}
	allowed, blocked, observed, outcome := findingOutcome(c.Outcome, c.Blocked)
	evidence := mergeEvidenceIDs("{}", c.EvidenceIDs)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO findings
			(finding_id, finding_key, generation, previous_finding_id, device_id, fallback_identity,
			 detector, category, primary_observable_type, primary_observable,
			 first_seen, last_seen, occurrence_count, maximum_score, current_priority,
				 allowed_count, blocked_count, observed_count, outcome, status, reason, recommended_action,
			 last_event_id, evidence, disposition, suppression_rule_id, created_at, updated_at,
			 resolved_at, resolution_reason)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
		id, c.FindingKey, generation, nullableString(previousID), nullableString(c.DeviceID), c.FallbackIdentity,
		c.Detector, c.Category, c.PrimaryObservableType, c.PrimaryObservable, when, when,
		c.Score, string(c.Priority), allowed, blocked, observed, outcome, c.Reason, c.RecommendedAction,
		eventID, evidence, string(c.Disposition), c.SuppressionRuleID, now, now,
	)
	if err != nil {
		return "", fmt.Errorf("insert finding generation: %w", err)
	}
	if _, err := linkFindingEvent(ctx, tx, id, eventID, when); err != nil {
		return "", err
	}
	if err := insertStatusHistory(ctx, tx, id, "", models.FindingStatusOpen, "finding created", "system", now); err != nil {
		return "", err
	}
	return id, nil
}

func reopenFinding(ctx context.Context, tx *sql.Tx, latest latestFinding, eventID string, c models.FindingCandidate, when time.Time) error {
	allowed, blocked, observed, outcome := findingOutcome(c.Outcome, c.Blocked)
	mergedEvidence := mergeEvidenceIDs(latest.Evidence, c.EvidenceIDs)
	_, err := tx.ExecContext(ctx, `
		UPDATE findings SET status = 'open', resolved_at = NULL, resolution_reason = '',
			first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?),
			occurrence_count = occurrence_count + 1,
			maximum_score = MAX(maximum_score, ?),
			current_priority = CASE WHEN maximum_score < ? THEN ? ELSE current_priority END,
			allowed_count = allowed_count + ?, blocked_count = blocked_count + ?, observed_count = observed_count + ?,
			outcome = CASE
				WHEN (((allowed_count + ?) > 0) + ((blocked_count + ?) > 0) + ((observed_count + ?) > 0)) > 1 THEN 'mixed'
				WHEN (blocked_count + ?) > 0 THEN 'blocked'
				WHEN (allowed_count + ?) > 0 THEN 'allowed' ELSE 'observed' END,
			reason = CASE WHEN ? >= maximum_score THEN ? ELSE reason END,
			recommended_action = CASE WHEN ? >= maximum_score THEN ? ELSE recommended_action END,
			last_event_id = ?, evidence = ?, disposition = ?, suppression_rule_id = ?, updated_at = ?
		WHERE finding_id = ?`,
		when, when, c.Score, c.Score, string(c.Priority), allowed, blocked, observed,
		allowed, blocked, observed, blocked, allowed, c.Score, c.Reason, c.Score, c.RecommendedAction,
		eventID, mergedEvidence, string(c.Disposition), c.SuppressionRuleID, time.Now().UTC(), latest.ID,
	)
	if err != nil {
		return fmt.Errorf("reopen finding: %w", err)
	}
	_ = outcome
	return insertStatusHistory(ctx, tx, latest.ID, models.FindingStatusResolved, models.FindingStatusOpen, "recurred within 7 days", "system", time.Now().UTC())
}

func linkFindingEvent(ctx context.Context, tx *sql.Tx, findingID, eventID string, when time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO finding_events (finding_id, event_id, linked_at) VALUES (?, ?, ?)`,
		findingID, eventID, when)
	if err != nil {
		return false, fmt.Errorf("link finding event: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("finding event rows affected: %w", err)
	}
	return rows == 1, nil
}

func linkFindingEvidence(ctx context.Context, tx *sql.Tx, findingID, evidenceID string) error {
	if strings.TrimSpace(evidenceID) == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id, linked_at)
		VALUES (?, ?, ?)`, findingID, evidenceID, time.Now().UTC()); err != nil {
		return fmt.Errorf("link finding evidence: %w", err)
	}
	return nil
}

func insertStatusHistory(ctx context.Context, tx *sql.Tx, findingID string, from, to models.FindingStatus, reason, actor string, when time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO finding_status_history
			(history_id, finding_id, from_status, to_status, reason, actor, changed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), findingID, string(from), string(to), reason, actor, when.UTC())
	if err != nil {
		return fmt.Errorf("insert finding status history: %w", err)
	}
	return nil
}

func findingOutcome(value string, blockedFlag bool) (allowed, blockedCount, observed int, outcome string) {
	switch value {
	case "blocked":
		return 0, 1, 0, "blocked"
	case "allowed":
		return 1, 0, 0, "allowed"
	case "observed":
		return 0, 0, 1, "observed"
	default:
		if blockedFlag {
			return 0, 1, 0, "blocked"
		}
		return 0, 0, 1, "observed"
	}
}

func mergeEvidenceIDs(existing string, additions []string) string {
	var doc struct {
		EvidenceIDs []string `json:"evidence_ids"`
	}
	_ = json.Unmarshal([]byte(existing), &doc)
	seen := make(map[string]struct{}, len(doc.EvidenceIDs)+len(additions))
	merged := make([]string, 0, len(doc.EvidenceIDs)+len(additions))
	for _, id := range append(doc.EvidenceIDs, additions...) {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		merged = append(merged, id)
	}
	doc.EvidenceIDs = merged
	if len(doc.EvidenceIDs) > findingEvidenceSummaryCap {
		doc.EvidenceIDs = doc.EvidenceIDs[len(doc.EvidenceIDs)-findingEvidenceSummaryCap:]
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func priorityForScore(score float64) models.Priority {
	switch {
	case score >= 0.85:
		return models.PriorityCritical
	case score >= 0.60:
		return models.PriorityHigh
	case score >= 0.30:
		return models.PriorityMedium
	default:
		return models.PriorityLow
	}
}

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

// FindingQueryParams controls the server-side findings list.
type FindingQueryParams struct {
	Status      models.FindingStatus
	ActiveOnly  bool
	Priority    models.Priority
	Disposition models.FindingDisposition
	DeviceID    string
	Page        int
	Limit       int
}

type FindingQueryResult struct {
	Findings []models.Finding `json:"findings"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	Limit    int              `json:"limit"`
}

// MaxFindingQueryLimit bounds a findings prefix to keep beta dashboard reads
// predictable while still allowing an operator to expand a queue deeply in a
// single, consistent SQLite snapshot.
const MaxFindingQueryLimit = 5000

// QueryFindings lists durable findings without loading raw supporting events.
func (db *DB) QueryFindings(ctx context.Context, params FindingQueryParams) (*FindingQueryResult, error) {
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 {
		params.Limit = 50
	}
	if params.Limit > MaxFindingQueryLimit {
		params.Limit = MaxFindingQueryLimit
	}
	conditions := []string{}
	args := []any{}
	if params.Status != "" {
		conditions = append(conditions, "f.status = ?")
		args = append(args, string(params.Status))
	} else if params.ActiveOnly {
		conditions = append(conditions, "f.status <> 'resolved'")
	}
	if params.Priority != "" {
		conditions = append(conditions, "f.current_priority = ?")
		args = append(args, string(params.Priority))
	}
	if params.Disposition != "" {
		conditions = append(conditions, "f.disposition = ?")
		args = append(args, string(params.Disposition))
	}
	if params.DeviceID != "" {
		// Findings keep the original device foreign key for exact split/undo.
		// Reads and filters follow the soft redirect to the canonical asset.
		conditions = append(conditions, "COALESCE(cd.canonical_id, f.device_id, '') = ?")
		args = append(args, params.DeviceID)
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}
	// Count and prefix are read in one transaction so the returned total and
	// ordered horizon describe the same database snapshot.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin findings query: %w", err)
	}
	defer tx.Rollback()
	var total int
	if err := tx.QueryRowContext(ctx, canonicalDeviceCTE+" SELECT COUNT(*) "+findingFromSQL+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}
	queryArgs := append(append([]any{}, args...), params.Limit, (params.Page-1)*params.Limit)
	rows, err := tx.QueryContext(ctx, canonicalDeviceCTE+findingSelectSQL+where+` ORDER BY
		CASE WHEN f.status = 'resolved' THEN 1 ELSE 0 END,
		CASE f.current_priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
		f.last_seen DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	findings := []models.Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close findings rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit findings query: %w", err)
	}
	return &FindingQueryResult{Findings: findings, Total: total, Page: params.Page, Limit: params.Limit}, nil
}

// GetFinding returns one durable finding.
func (db *DB) GetFinding(ctx context.Context, findingID string) (*models.Finding, error) {
	f, err := scanFinding(db.QueryRowContext(ctx, canonicalDeviceCTE+findingSelectSQL+` WHERE f.finding_id = ?`, findingID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFindingNotFound
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// FindingEvidence returns every immutable detector result supporting a finding.
func (db *DB) FindingEvidence(ctx context.Context, findingID string) ([]models.DetectionEvidence, error) {
	return db.FindingEvidencePage(ctx, findingID, 100, 0)
}

// FindingEvidencePage returns a bounded evidence page for browser drill-down.
func (db *DB) FindingEvidencePage(ctx context.Context, findingID string, limit, offset int) ([]models.DetectionEvidence, error) {
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.QueryContext(ctx, `
		SELECT e.evidence_id, e.event_id, e.detector, e.category, e.observable_type,
		       e.observable_value, e.threat_source, e.source_confidence, e.feed_freshness,
		       e.feed_stale, e.rationale, e.score_contribution, e.outcome,
		       e.device_context, e.details, e.created_at
		FROM event_detection_evidence e
		JOIN finding_evidence fe ON fe.evidence_id = e.evidence_id
		WHERE fe.finding_id = ? ORDER BY e.created_at DESC, e.evidence_id DESC
		LIMIT ? OFFSET ?`, findingID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query finding evidence: %w", err)
	}
	defer rows.Close()
	out := []models.DetectionEvidence{}
	for rows.Next() {
		var e models.DetectionEvidence
		var feedFreshness sql.NullTime
		var deviceContext, details string
		if err := rows.Scan(&e.EvidenceID, &e.EventID, &e.Detector, &e.Category,
			&e.ObservableType, &e.ObservableValue, &e.ThreatSource, &e.SourceConfidence,
			&feedFreshness, &e.FeedStale, &e.Rationale, &e.ScoreContribution, &e.Outcome,
			&deviceContext, &details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding evidence: %w", err)
		}
		if feedFreshness.Valid {
			t := feedFreshness.Time
			e.FeedFreshness = &t
		}
		e.DeviceContext = json.RawMessage(deviceContext)
		e.Details = json.RawMessage(details)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) CountFindingEvidence(ctx context.Context, findingID string) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_evidence WHERE finding_id = ?`, findingID).Scan(&count)
	return count, err
}

func (db *DB) CountFindingEvents(ctx context.Context, findingID string) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_events WHERE finding_id = ?`, findingID).Scan(&count)
	return count, err
}

// FindingStatusHistory returns the append-only lifecycle audit trail.
func (db *DB) FindingStatusHistory(ctx context.Context, findingID string) ([]models.FindingStatusHistory, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT history_id, finding_id, from_status, to_status, reason, actor, changed_at
		FROM finding_status_history WHERE finding_id = ? ORDER BY changed_at ASC, history_id ASC`, findingID)
	if err != nil {
		return nil, fmt.Errorf("query finding status history: %w", err)
	}
	defer rows.Close()
	out := []models.FindingStatusHistory{}
	for rows.Next() {
		var history models.FindingStatusHistory
		if err := rows.Scan(&history.HistoryID, &history.FindingID, &history.FromStatus,
			&history.ToStatus, &history.Reason, &history.Actor, &history.ChangedAt); err != nil {
			return nil, fmt.Errorf("scan finding status history: %w", err)
		}
		out = append(out, history)
	}
	return out, rows.Err()
}

// FindingSupportingEvents returns full immutable events for evidence drill-down.
// Results are newest-first and bounded for the Pi-class deployment floor.
func (db *DB) FindingSupportingEvents(ctx context.Context, findingID string, limit, offset int) ([]models.Event, error) {
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.QueryContext(ctx, canonicalDeviceCTE+`
			SELECT e.event_id, e.timestamp, e.event_type, e.source_hash,
		       COALESCE(e.source_ip, ''), COALESCE(e.server_ip, ''), COALESCE(e.domain, ''), COALESCE(e.query_type, ''),
		       COALESCE(e.resolved_ip, ''), e.blocked, COALESCE(e.outcome, 'observed'), e.anomaly_score,
		       COALESCE(e.tags, '[]'), COALESCE(e.geo, ''), COALESCE(e.device_vendor, ''),
		       COALESCE(e.network_segment, 'default'), COALESCE(e.dns_source, ''),
		       COALESCE(e.threat_desc, ''), COALESCE(e.metadata, '{}'),
		       COALESCE(e.acknowledged, FALSE), COALESCE(e.ack_reason, ''),
		       COALESCE(e.matched_indicator, ''), COALESCE(e.match_type, ''),
		       COALESCE(e.device_id, ''), COALESCE(cd.canonical_id, e.device_id, ''),
		       COALESCE(e.identity_confidence, 0),
		       COALESCE(e.identity_reason, ''), COALESCE(e.identity_evidence, '{}'),
		       COALESCE(e.origin, ''), COALESCE(e.sensor_id, ''),
		       COALESCE(e.disposition, 'active'), COALESCE(e.suppression_rule_id, '')
		FROM events e JOIN finding_events fe ON fe.event_id = e.event_id
			LEFT JOIN canonical_devices cd ON cd.root_id = e.device_id
		WHERE fe.finding_id = ? ORDER BY e.timestamp DESC, e.event_id DESC LIMIT ? OFFSET ?`, findingID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query finding events: %w", err)
	}
	defer rows.Close()
	out := []models.Event{}
	for rows.Next() {
		var event models.Event
		var tags string
		if err := rows.Scan(
			&event.EventID, &event.Timestamp, &event.EventType, &event.SourceHash,
			&event.SourceIP, &event.ServerIP, &event.Domain, &event.QueryType,
			&event.ResolvedIP, &event.Blocked, &event.Outcome, &event.AnomalyScore, &tags,
			&event.Geo, &event.DeviceVendor, &event.NetworkSegment, &event.DNSSource,
			&event.ThreatDesc, &event.Metadata, &event.Acknowledged, &event.AckReason,
			&event.MatchedIndicator, &event.MatchType, &event.DeviceID, &event.CanonicalDeviceID,
			&event.IdentityConfidence, &event.IdentityReason, &event.IdentityEvidence,
			&event.Origin, &event.SensorID, &event.Disposition, &event.SuppressionRuleID,
		); err != nil {
			return nil, fmt.Errorf("scan finding event: %w", err)
		}
		_ = json.Unmarshal([]byte(tags), &event.Tags)
		if event.Tags == nil {
			event.Tags = []string{}
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

type FindingStats struct {
	OpenByPriority   map[models.Priority]int `json:"open_by_priority"`
	AffectedDevices  int                     `json:"affected_devices"`
	RecentlyResolved int                     `json:"recently_resolved"`
	CalculatedAt     time.Time               `json:"calculated_at"`
}

// GetFindingStats returns current actionable state. Suppressed findings remain
// queryable evidence but do not inflate the operator's open-alert counters.
func (db *DB) GetFindingStats(ctx context.Context, recentlyResolvedWindow time.Duration) (FindingStats, error) {
	if recentlyResolvedWindow <= 0 {
		recentlyResolvedWindow = 7 * 24 * time.Hour
	}
	now := time.Now().UTC()
	stats := FindingStats{CalculatedAt: now, OpenByPriority: map[models.Priority]int{
		models.PriorityCritical: 0,
		models.PriorityHigh:     0,
		models.PriorityMedium:   0,
		models.PriorityLow:      0,
	}}
	rows, err := db.QueryContext(ctx, `
		SELECT current_priority, COUNT(*) FROM findings
		WHERE status <> 'resolved' AND disposition = 'active'
		GROUP BY current_priority`)
	if err != nil {
		return stats, fmt.Errorf("count open findings: %w", err)
	}
	for rows.Next() {
		var priority models.Priority
		var count int
		if err := rows.Scan(&priority, &count); err != nil {
			rows.Close()
			return stats, fmt.Errorf("scan open finding count: %w", err)
		}
		stats.OpenByPriority[priority] = count
	}
	if err := rows.Close(); err != nil {
		return stats, err
	}
	if err := db.QueryRowContext(ctx, canonicalDeviceCTE+`
			SELECT COUNT(DISTINCT CASE
				WHEN COALESCE(cd.canonical_id, f.device_id, '') <> ''
				THEN 'device:' || COALESCE(cd.canonical_id, f.device_id)
				ELSE 'fallback:' || f.fallback_identity END)
			FROM findings f LEFT JOIN canonical_devices cd ON cd.root_id = f.device_id
		WHERE f.status <> 'resolved' AND f.disposition = 'active'`).Scan(&stats.AffectedDevices); err != nil {
		return stats, fmt.Errorf("count affected devices: %w", err)
	}
	cutoff := now.Add(-recentlyResolvedWindow)
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM findings WHERE status = 'resolved' AND resolved_at >= ?`, cutoff).
		Scan(&stats.RecentlyResolved); err != nil {
		return stats, fmt.Errorf("count recently resolved findings: %w", err)
	}
	return stats, nil
}

// UpdateFindingStatus performs an audited lifecycle transition. Resolution
// requires an operator reason and never changes supporting events.
func (db *DB) UpdateFindingStatus(ctx context.Context, findingID string, to models.FindingStatus, reason, actor string) error {
	if to != models.FindingStatusOpen && to != models.FindingStatusInvestigating && to != models.FindingStatusResolved {
		return ErrInvalidFindingStatus
	}
	if to == models.FindingStatusResolved && strings.TrimSpace(reason) == "" {
		return ErrResolutionReasonRequired
	}
	if actor == "" {
		actor = "admin"
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin finding status: %w", err)
	}
	defer tx.Rollback()
	var from models.FindingStatus
	if err := tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE finding_id = ?`, findingID).Scan(&from); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return fmt.Errorf("load finding status: %w", err)
	}
	if from == to {
		return tx.Commit()
	}
	now := time.Now().UTC()
	var resolvedAt any
	resolutionReason := ""
	if to == models.FindingStatusResolved {
		resolvedAt = now
		resolutionReason = strings.TrimSpace(reason)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET status = ?, resolved_at = ?, resolution_reason = ?, updated_at = ?
		WHERE finding_id = ?`, string(to), resolvedAt, resolutionReason, now, findingID); err != nil {
		return fmt.Errorf("update finding status: %w", err)
	}
	if err := insertStatusHistory(ctx, tx, findingID, from, to, reason, actor, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit finding status: %w", err)
	}
	return nil
}

const canonicalDeviceCTE = `
WITH RECURSIVE device_chain(root_id, current_id, depth) AS (
    SELECT device_id, device_id, 0 FROM devices
    UNION ALL
    SELECT c.root_id, d.merged_into_device_id, c.depth + 1
    FROM device_chain c JOIN devices d ON d.device_id = c.current_id
    WHERE d.merged_into_device_id IS NOT NULL AND d.merged_into_device_id <> '' AND c.depth < 32
), canonical_devices(root_id, canonical_id) AS (
    SELECT c.root_id, c.current_id
    FROM device_chain c JOIN devices d ON d.device_id = c.current_id
    WHERE d.merged_into_device_id IS NULL OR d.merged_into_device_id = ''
)
`

const findingFromSQL = `FROM findings f
	LEFT JOIN canonical_devices cd ON cd.root_id = f.device_id
	LEFT JOIN events le ON le.event_id = f.last_event_id`

const findingSelectSQL = `
	SELECT f.finding_id, f.finding_key, f.generation, COALESCE(f.previous_finding_id, ''),
	       COALESCE(f.device_id, ''), COALESCE(cd.canonical_id, f.device_id, ''),
	       COALESCE(le.identity_confidence, 0), COALESCE(le.identity_reason, ''),
	       f.fallback_identity, f.detector, f.category,
	       f.primary_observable_type, f.primary_observable, f.first_seen, f.last_seen,
	       f.occurrence_count, f.maximum_score, f.current_priority, f.allowed_count,
	       f.blocked_count, f.observed_count, f.outcome, f.status, f.reason, f.recommended_action,
	       COALESCE(f.last_event_id, ''), f.evidence, f.disposition, f.suppression_rule_id,
	       f.created_at, f.updated_at, f.resolved_at, f.resolution_reason
	` + findingFromSQL

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFinding(row rowScanner) (models.Finding, error) {
	var f models.Finding
	var evidence string
	var resolvedAt sql.NullTime
	if err := row.Scan(
		&f.FindingID, &f.FindingKey, &f.Generation, &f.PreviousFindingID,
		&f.DeviceID, &f.CanonicalDeviceID, &f.IdentityConfidence, &f.IdentityReason,
		&f.FallbackIdentity, &f.Detector, &f.Category,
		&f.PrimaryObservableType, &f.PrimaryObservable, &f.FirstSeen, &f.LastSeen,
		&f.OccurrenceCount, &f.MaximumScore, &f.CurrentPriority, &f.AllowedCount,
		&f.BlockedCount, &f.ObservedCount, &f.Outcome, &f.Status, &f.Reason, &f.RecommendedAction,
		&f.LastEventID, &evidence, &f.Disposition, &f.SuppressionRuleID,
		&f.CreatedAt, &f.UpdatedAt, &resolvedAt, &f.ResolutionReason,
	); err != nil {
		return f, err
	}
	f.Evidence = json.RawMessage(evidence)
	f.NeedsIdentification = f.DeviceID == "" || f.IdentityConfidence < 0.75 ||
		strings.Contains(strings.ToLower(f.IdentityReason), "conflict") ||
		strings.Contains(strings.ToLower(f.IdentityReason), "ambiguous")
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
	return f, nil
}
