package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// AcknowledgeEvent marks an event as acknowledged with an optional reason.
func (db *DB) AcknowledgeEvent(eventID, reason string) error {
	_, err := db.Exec(`UPDATE events SET acknowledged = TRUE, ack_reason = ? WHERE event_id = ?`, reason, eventID)
	if err != nil {
		return fmt.Errorf("ack event: %w", err)
	}
	return nil
}

// UnacknowledgeEvent removes the acknowledgment from an event.
func (db *DB) UnacknowledgeEvent(eventID string) error {
	_, err := db.Exec(`UPDATE events SET acknowledged = FALSE, ack_reason = '' WHERE event_id = ?`, eventID)
	if err != nil {
		return fmt.Errorf("unack event: %w", err)
	}
	return nil
}

// CreateSuppressionRule creates a new suppression rule.
func (db *DB) CreateSuppressionRule(domain, sourceIP string, tags []string, reason string) (*models.SuppressionRule, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	tagsJSON, _ := json.Marshal(tags)
	if len(tags) == 0 {
		tagsJSON = []byte("[]")
	}

	_, err := db.Exec(`
		INSERT INTO suppression_rules (rule_id, created_at, domain, source_ip, tags, reason, active)
		VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
		id, now, domain, sourceIP, string(tagsJSON), reason)
	if err != nil {
		return nil, fmt.Errorf("create suppression rule: %w", err)
	}

	return &models.SuppressionRule{
		RuleID:    id,
		CreatedAt: now,
		Domain:    domain,
		SourceIP:  sourceIP,
		Tags:      tags,
		Reason:    reason,
		Active:    true,
	}, nil
}

// ListSuppressionRules returns all suppression rules.
func (db *DB) ListSuppressionRules() ([]models.SuppressionRule, error) {
	rows, err := db.Query(`
		SELECT rule_id, created_at, COALESCE(domain, ''), COALESCE(source_ip, ''),
		       COALESCE(tags, '[]'), COALESCE(reason, ''), active
		FROM suppression_rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list suppression rules: %w", err)
	}
	defer rows.Close()

	var rules []models.SuppressionRule
	for rows.Next() {
		var r models.SuppressionRule
		var tagsJSON string
		if err := rows.Scan(&r.RuleID, &r.CreatedAt, &r.Domain, &r.SourceIP, &tagsJSON, &r.Reason, &r.Active); err != nil {
			return nil, fmt.Errorf("scan suppression rule: %w", err)
		}
		json.Unmarshal([]byte(tagsJSON), &r.Tags)
		if r.Tags == nil {
			r.Tags = []string{}
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []models.SuppressionRule{}
	}
	return rules, rows.Err()
}

// DeleteSuppressionRule removes a suppression rule.
func (db *DB) DeleteSuppressionRule(ruleID string) error {
	_, err := db.Exec(`DELETE FROM suppression_rules WHERE rule_id = ?`, ruleID)
	if err != nil {
		return fmt.Errorf("delete suppression rule: %w", err)
	}
	return nil
}
