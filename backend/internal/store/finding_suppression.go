package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

var (
	ErrFindingSuppressionNotFound       = errors.New("finding suppression rule not found")
	ErrFindingSuppressionReasonRequired = errors.New("suppression reason is required")
)

// SuppressFinding creates or reuses an exact typed rule and immediately changes
// this finding's disposition. Evidence and lifecycle state are untouched.
func (db *DB) SuppressFinding(ctx context.Context, findingID, reason, actor string) (*models.FindingSuppressionRule, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrFindingSuppressionReasonRequired
	}
	if actor == "" {
		actor = "admin"
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin finding suppression: %w", err)
	}
	defer tx.Rollback()

	var detector, observableType, observableValue, fallbackIdentity string
	var rawDeviceID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT detector, primary_observable_type, primary_observable, device_id, fallback_identity
		FROM findings WHERE finding_id = ?`, findingID).
		Scan(&detector, &observableType, &observableValue, &rawDeviceID, &fallbackIdentity); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, fmt.Errorf("load finding for suppression: %w", err)
	}

	deviceID := strings.TrimSpace(rawDeviceID.String)
	if deviceID != "" {
		deviceID, err = dbCanonicalDeviceIDTx(tx, deviceID)
		if err != nil {
			return nil, fmt.Errorf("resolve suppression device: %w", err)
		}
		fallbackIdentity = ""
	}
	detector = strings.TrimSpace(detector)
	observableType = strings.TrimSpace(observableType)
	observableValue = strings.TrimSpace(observableValue)

	rule := models.FindingSuppressionRule{}
	var storedDeviceID sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT rule_id, created_at, updated_at, detector, observable_type,
		       observable_value, device_id, fallback_identity, reason, active
		FROM finding_suppression_rules
		WHERE active = TRUE AND detector = ? AND observable_type = ?
		  AND observable_value = ? AND COALESCE(device_id, '') = ? AND fallback_identity = ?
		ORDER BY created_at ASC LIMIT 1`, detector, observableType, observableValue, deviceID, fallbackIdentity).
		Scan(&rule.RuleID, &rule.CreatedAt, &rule.UpdatedAt, &rule.Detector, &rule.ObservableType,
			&rule.ObservableValue, &storedDeviceID, &rule.FallbackIdentity, &rule.Reason, &rule.Active)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("find existing suppression rule: %w", err)
	}
	now := time.Now().UTC()
	if errors.Is(err, sql.ErrNoRows) {
		rule = models.FindingSuppressionRule{
			RuleID: uuid.NewString(), CreatedAt: now, UpdatedAt: now,
			Detector: detector, ObservableType: observableType, ObservableValue: observableValue,
			DeviceID: deviceID, FallbackIdentity: fallbackIdentity, Reason: reason, Active: true,
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_suppression_rules
				(rule_id, created_at, updated_at, detector, observable_type,
				 observable_value, device_id, fallback_identity, reason, active)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)`,
			rule.RuleID, now, now, detector, observableType, observableValue,
			nullableString(deviceID), fallbackIdentity, reason); err != nil {
			return nil, fmt.Errorf("create finding suppression rule: %w", err)
		}
	} else {
		rule.DeviceID = storedDeviceID.String
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET disposition = 'suppressed', suppression_rule_id = ?, updated_at = ?
		WHERE finding_id = ?`, rule.RuleID, now, findingID); err != nil {
		return nil, fmt.Errorf("suppress finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_suppression_history
			(history_id, rule_id, finding_id, action, reason, actor, changed_at)
		VALUES (?, ?, ?, 'activated', ?, ?, ?)`, uuid.NewString(), rule.RuleID, findingID, reason, actor, now); err != nil {
		return nil, fmt.Errorf("audit finding suppression: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit finding suppression: %w", err)
	}
	return &rule, nil
}

// DeactivateFindingSuppression turns off a policy and makes findings directly
// dispositioned by it actionable again. It never deletes evidence or history.
func (db *DB) DeactivateFindingSuppression(ctx context.Context, ruleID, actor string) (int64, error) {
	if actor == "" {
		actor = "admin"
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin suppression deactivation: %w", err)
	}
	defer tx.Rollback()

	var active bool
	var reason string
	if err := tx.QueryRowContext(ctx, `SELECT active, reason FROM finding_suppression_rules WHERE rule_id = ?`, ruleID).
		Scan(&active, &reason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrFindingSuppressionNotFound
		}
		return 0, fmt.Errorf("load finding suppression rule: %w", err)
	}
	if !active {
		return 0, tx.Commit()
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_suppression_rules SET active = FALSE, updated_at = ? WHERE rule_id = ?`, now, ruleID); err != nil {
		return 0, fmt.Errorf("deactivate finding suppression rule: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE findings SET disposition = 'active', suppression_rule_id = '', updated_at = ?
		WHERE suppression_rule_id = ?`, now, ruleID)
	if err != nil {
		return 0, fmt.Errorf("unsuppress findings: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count unsuppressed findings: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_suppression_history
			(history_id, rule_id, finding_id, action, reason, actor, changed_at)
		VALUES (?, ?, NULL, 'deactivated', ?, ?, ?)`, uuid.NewString(), ruleID, reason, actor, now); err != nil {
		return 0, fmt.Errorf("audit suppression deactivation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit suppression deactivation: %w", err)
	}
	return affected, nil
}

func (db *DB) ListFindingSuppressionRules(ctx context.Context) ([]models.FindingSuppressionRule, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT rule_id, created_at, updated_at, detector, observable_type,
		       observable_value, device_id, fallback_identity, reason, active
		FROM finding_suppression_rules ORDER BY active DESC, updated_at DESC, rule_id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list finding suppression rules: %w", err)
	}
	defer rows.Close()
	rules := []models.FindingSuppressionRule{}
	for rows.Next() {
		var rule models.FindingSuppressionRule
		var deviceID sql.NullString
		if err := rows.Scan(&rule.RuleID, &rule.CreatedAt, &rule.UpdatedAt, &rule.Detector,
			&rule.ObservableType, &rule.ObservableValue, &deviceID, &rule.FallbackIdentity, &rule.Reason, &rule.Active); err != nil {
			return nil, fmt.Errorf("scan finding suppression rule: %w", err)
		}
		rule.DeviceID = deviceID.String
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}
