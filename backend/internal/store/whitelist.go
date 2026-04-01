package store

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// CreateWhitelistRule creates a new whitelist rule. If rule_id is empty, generates UUID.
func (db *DB) CreateWhitelistRule(rule models.WhitelistRule) (*models.WhitelistRule, error) {
	if rule.RuleID == "" {
		rule.RuleID = uuid.New().String()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}

	_, err := db.Exec(`
		INSERT INTO whitelist_rules (rule_id, name, description, domain_pattern, source_ip_pattern,
		                             tag_match, category, is_default, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.RuleID, rule.Name, rule.Description, rule.DomainPattern, rule.SourceIPPattern,
		rule.TagMatch, rule.Category, rule.IsDefault, rule.Enabled, rule.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create whitelist rule: %w", err)
	}

	return &rule, nil
}

// ListWhitelistRules returns all whitelist rules ordered by category, then name.
func (db *DB) ListWhitelistRules() ([]models.WhitelistRule, error) {
	rows, err := db.Query(`
		SELECT rule_id, name, COALESCE(description, ''), COALESCE(domain_pattern, ''),
		       COALESCE(source_ip_pattern, ''), COALESCE(tag_match, ''), category, is_default,
		       enabled, created_at
		FROM whitelist_rules
		ORDER BY category, name`)
	if err != nil {
		return nil, fmt.Errorf("list whitelist rules: %w", err)
	}
	defer rows.Close()

	var rules []models.WhitelistRule
	for rows.Next() {
		var r models.WhitelistRule
		if err := rows.Scan(&r.RuleID, &r.Name, &r.Description, &r.DomainPattern, &r.SourceIPPattern,
			&r.TagMatch, &r.Category, &r.IsDefault, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan whitelist rule: %w", err)
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []models.WhitelistRule{}
	}
	return rules, rows.Err()
}

// UpdateWhitelistRule toggles the enabled state of a whitelist rule.
func (db *DB) UpdateWhitelistRule(ruleID string, enabled bool) error {
	_, err := db.Exec(`UPDATE whitelist_rules SET enabled = ? WHERE rule_id = ?`, enabled, ruleID)
	if err != nil {
		return fmt.Errorf("update whitelist rule: %w", err)
	}
	return nil
}

// DeleteWhitelistRule removes a whitelist rule. Only allows deleting non-default rules.
func (db *DB) DeleteWhitelistRule(ruleID string) error {
	// Check if it's a default rule
	var isDefault bool
	err := db.QueryRow(`SELECT is_default FROM whitelist_rules WHERE rule_id = ?`, ruleID).Scan(&isDefault)
	if err != nil {
		return fmt.Errorf("check whitelist rule: %w", err)
	}
	if isDefault {
		return fmt.Errorf("cannot delete default whitelist rule: %s", ruleID)
	}

	_, err = db.Exec(`DELETE FROM whitelist_rules WHERE rule_id = ?`, ruleID)
	if err != nil {
		return fmt.Errorf("delete whitelist rule: %w", err)
	}
	return nil
}

// SeedDefaultWhitelistRules inserts default whitelist rules if none exist with is_default=TRUE.
func (db *DB) SeedDefaultWhitelistRules() error {
	// Check if any default rules already exist
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM whitelist_rules WHERE is_default = TRUE`).Scan(&count)
	if err != nil {
		return fmt.Errorf("check default rules: %w", err)
	}
	if count > 0 {
		// Default rules already seeded
		return nil
	}

	defaultRules := []models.WhitelistRule{
		{
			RuleID:        uuid.New().String(),
			Name:          "Apple Services",
			DomainPattern: "*.apple.com",
			Category:      "apple",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "iCloud",
			DomainPattern: "*.icloud.com",
			Category:      "apple",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Apple CDN",
			DomainPattern: "*.cdn-apple.com",
			Category:      "apple",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Apple Push",
			DomainPattern: "*.push.apple.com",
			TagMatch:      "beaconing",
			Category:      "apple",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Bonjour/mDNS",
			DomainPattern: "*.local",
			Category:      "mdns",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "mDNS Service Discovery",
			DomainPattern: "_tcp.local",
			Category:      "mdns",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "mDNS UDP Discovery",
			DomainPattern: "_udp.local",
			Category:      "mdns",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Multicast DNS",
			DomainPattern: "*.mcast.net",
			Category:      "mdns",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Google Services",
			DomainPattern: "*.google.com",
			TagMatch:      "beaconing",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Google APIs",
			DomainPattern: "*.googleapis.com",
			TagMatch:      "beaconing",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Googlecast",
			DomainPattern: "*.googlecast.com",
			Category:      "iot",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Microsoft Services",
			DomainPattern: "*.microsoft.com",
			TagMatch:      "beaconing",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Windows Update",
			DomainPattern: "*.windowsupdate.com",
			Category:      "os_updates",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Ubuntu Updates",
			DomainPattern: "*.ubuntu.com",
			Category:      "os_updates",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "NTP",
			DomainPattern: "*.ntp.org",
			TagMatch:      "beaconing",
			Category:      "os_updates",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Amazon AWS",
			DomainPattern: "*.amazonaws.com",
			TagMatch:      "beaconing",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Cloudflare DNS",
			SourceIPPattern: "1.1.1.1",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Akamai CDN",
			DomainPattern: "*.akamaiedge.net",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Netflix",
			DomainPattern: "*.netflix.com",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
		{
			RuleID:        uuid.New().String(),
			Name:          "Spotify",
			DomainPattern: "*.spotify.com",
			TagMatch:      "beaconing",
			Category:      "cloud",
			IsDefault:     true,
			Enabled:       true,
		},
	}

	for _, rule := range defaultRules {
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = time.Now().UTC()
		}
		_, err := db.CreateWhitelistRule(rule)
		if err != nil {
			return fmt.Errorf("seed default rule %s: %w", rule.Name, err)
		}
	}

	return nil
}
