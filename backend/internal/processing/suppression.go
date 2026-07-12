package processing

import (
	"context"
	"fmt"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// StoreSuppressionEvaluator evaluates both backward-compatible event rules and
// the new typed finding policies. A match changes disposition only.
type StoreSuppressionEvaluator struct {
	DB *store.DB
}

func (e StoreSuppressionEvaluator) EvaluateSuppression(ctx context.Context, in SuppressionInput) (SuppressionDecision, error) {
	if e.DB == nil {
		return SuppressionDecision{}, nil
	}
	legacy, err := e.DB.FindMatchingSuppressionRule(
		in.Event.Domain, in.Event.SourceIP, in.Event.DeviceVendor,
		in.Event.NetworkSegment, in.Event.Tags,
	)
	if err != nil {
		return SuppressionDecision{}, err
	}
	if legacy != nil {
		return SuppressionDecision{Suppressed: true, RuleID: legacy.RuleID, Reason: legacy.Reason}, nil
	}

	decision := SuppressionDecision{Evidence: map[string]SuppressionMatch{}}
	deviceID := in.DeviceID
	if strings.TrimSpace(deviceID) != "" {
		canonicalID, err := e.DB.CanonicalDeviceID(ctx, deviceID)
		if err != nil {
			return SuppressionDecision{}, fmt.Errorf("resolve suppression device: %w", err)
		}
		deviceID = canonicalID
	}
	for _, evidence := range in.Evidence {
		type candidateRule struct {
			ruleID, reason, deviceID, fallbackIdentity string
		}
		rows, err := e.DB.QueryContext(ctx, `
			SELECT rule_id, reason, COALESCE(device_id, ''), fallback_identity
			FROM finding_suppression_rules
			WHERE active = TRUE
			  AND (detector = '' OR detector = ?)
			  AND (observable_type = '' OR observable_type = ?)
			  AND (observable_value = '' OR observable_value = ?)
			ORDER BY created_at ASC`,
			evidence.Detector, evidence.ObservableType, evidence.ObservableValue,
		)
		if err != nil {
			return SuppressionDecision{}, fmt.Errorf("evaluate finding suppression: %w", err)
		}
		candidates := []candidateRule{}
		for rows.Next() {
			var rule candidateRule
			if err := rows.Scan(&rule.ruleID, &rule.reason, &rule.deviceID, &rule.fallbackIdentity); err != nil {
				rows.Close()
				return SuppressionDecision{}, fmt.Errorf("scan finding suppression: %w", err)
			}
			candidates = append(candidates, rule)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return SuppressionDecision{}, fmt.Errorf("iterate finding suppression: %w", err)
		}
		if err := rows.Close(); err != nil {
			return SuppressionDecision{}, fmt.Errorf("close finding suppression: %w", err)
		}
		for _, rule := range candidates {
			matches := rule.deviceID == "" && rule.fallbackIdentity == ""
			if rule.deviceID != "" && deviceID != "" {
				canonicalRuleDevice, err := e.DB.CanonicalDeviceID(ctx, rule.deviceID)
				if err != nil {
					return SuppressionDecision{}, fmt.Errorf("resolve suppression rule device: %w", err)
				}
				matches = canonicalRuleDevice == deviceID
			} else if rule.deviceID == "" && rule.fallbackIdentity != "" {
				matches = rule.fallbackIdentity == in.FallbackIdentity
			}
			if matches {
				decision.Evidence[evidence.EvidenceID] = SuppressionMatch{RuleID: rule.ruleID, Reason: rule.reason}
				break
			}
		}
	}
	return decision, nil
}

// NormalizeSuppressionValue is shared by handlers creating exact-match rules.
func NormalizeSuppressionValue(observableType, value string) string {
	return normalizeObservable(strings.TrimSpace(observableType), value)
}
