package processing

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

var coreOwnedTags = map[string]struct{}{
	"known_bad": {}, "community_advisory": {},
	"c2": {}, "c2_candidate": {}, "botnet": {}, "malware": {}, "malware_distribution": {}, "phishing": {},
	"dga": {}, "dga_candidate": {}, "dns_tunnel": {}, "dns_tunneling": {}, "tunneling_candidate": {},
	"beaconing": {}, "beaconing_candidate": {}, "dns_rebinding": {}, "dns_bypass": {},
	"ips": {}, "new_fw_block": {}, "risky_device_fw_block": {}, "newly_registered": {},
	"whitelisted": {}, "known_good_context": {}, "vedetta_self": {}, "wan_scan_noise": {},
	"new_device": {}, "very_new_device": {}, "new_device_context": {}, "iot_context": {},
	"eol_router": {}, "eol_device_context": {}, "high_risk_iot": {}, "known_exploited": {},
	"source:unifi": {},
}

type trustedIPS struct {
	Valid    bool
	Severity int
}

// sanitizeIngressEvent removes every verdict, detector, benign, and device
// context value that Core owns. Original values remain namespaced source audit
// material, but can never influence evidence or finding creation.
func sanitizeIngressEvent(event *models.Event, envelope *IngressEnvelope) trustedIPS {
	trusted := validateTrustedIPS(*event, envelope.Origin)
	if envelope.SourceMeta == nil {
		envelope.SourceMeta = map[string]any{}
	} else {
		envelope.SourceMeta = cloneObject(envelope.SourceMeta)
	}
	if len(event.Tags) > 0 {
		envelope.SourceMeta["ingress_tags"] = append([]string(nil), event.Tags...)
	}
	fields := map[string]any{}
	if event.AnomalyScore != 0 {
		fields["anomaly_score"] = event.AnomalyScore
	}
	if event.ThreatDesc != "" {
		fields["threat_desc"] = event.ThreatDesc
	}
	if event.DeviceVendor != "" {
		fields["device_vendor"] = event.DeviceVendor
	}
	if event.MatchType != "" || event.MatchedIndicator != "" {
		fields["match_type"] = event.MatchType
		fields["matched_indicator"] = event.MatchedIndicator
	}
	if event.DeviceID != "" || event.IdentityConfidence != 0 || event.IdentityReason != "" || event.IdentityEvidence != "" ||
		event.Origin != "" || event.SensorID != "" || event.Disposition != "" || event.SuppressionRuleID != "" || event.Outcome != "" {
		fields["device_id"] = event.DeviceID
		fields["identity_confidence"] = event.IdentityConfidence
		fields["identity_reason"] = event.IdentityReason
		fields["identity_evidence"] = event.IdentityEvidence
		fields["origin"] = event.Origin
		fields["sensor_id"] = event.SensorID
		fields["disposition"] = event.Disposition
		fields["suppression_rule_id"] = event.SuppressionRuleID
		fields["outcome"] = event.Outcome
	}
	if len(fields) > 0 {
		envelope.SourceMeta["ingress_core_fields"] = fields
	}

	kept := make([]string, 0, len(event.Tags))
	for _, tag := range event.Tags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		if _, owned := coreOwnedTags[normalized]; owned || strings.HasPrefix(normalized, "fw:") || strings.HasPrefix(normalized, "dir:") {
			continue
		}
		kept = append(kept, tag)
	}
	event.Tags = kept
	if validateTrustedRollup(*event, envelope.Origin) {
		event.Tags = appendUniqueString(event.Tags, "wan_scan_noise")
	}
	event.AnomalyScore = 0
	event.ThreatDesc = ""
	event.DeviceVendor = ""
	event.MatchType = ""
	event.MatchedIndicator = ""
	event.DeviceID = ""
	event.IdentityConfidence = 0
	event.IdentityReason = ""
	event.IdentityEvidence = ""
	event.Origin = ""
	event.SensorID = ""
	event.Disposition = ""
	event.SuppressionRuleID = ""
	event.Outcome = ""
	return trusted
}

func deriveIngressOutcome(event models.Event, envelope IngressEnvelope) string {
	if event.Blocked {
		return "blocked"
	}
	origin := strings.ToLower(strings.TrimSpace(envelope.Origin))
	dnsSource := strings.ToLower(strings.TrimSpace(event.DNSSource))
	if origin == "pihole" || origin == "adguard" || dnsSource == "pihole" || dnsSource == "adguard" {
		// These filtering APIs report an explicit disposition for every query.
		return "allowed"
	}
	if event.EventType == "firewall_log" {
		action, _ := decodeObject(event.Metadata)["action"].(string)
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "block", "drop", "reject", "deny":
			return "blocked"
		case "allow", "accept", "pass":
			return "allowed"
		}
	}
	// Passive DNS and generic log sources often prove only that activity was
	// observed. A missing boolean must never be presented as affirmative allow.
	return "observed"
}

func validateTrustedRollup(event models.Event, origin string) bool {
	if strings.TrimSpace(origin) != "collector" || event.EventType != "firewall_log" {
		return false
	}
	meta := decodeObject(event.Metadata)
	rollup, _ := meta["rollup"].(bool)
	dialect, _ := meta["dialect"].(string)
	count, ok := strictInt(meta["count"])
	return rollup && dialect == "iptables" && ok && count > 1
}

func validateTrustedIPS(event models.Event, origin string) trustedIPS {
	if strings.TrimSpace(origin) != "unifi_rest" || event.EventType != "firewall_log" || !hasAnyTag(event.Tags, "ips") {
		return trustedIPS{}
	}
	meta := decodeObject(event.Metadata)
	dialect, _ := meta["dialect"].(string)
	severity, ok := strictInt(meta["ips_severity"])
	if !ok || dialect != "rest" || severity < 1 || severity > 3 {
		return trustedIPS{}
	}
	return trustedIPS{Valid: true, Severity: severity}
}

func applyTrustedIPS(event *models.Event, trusted trustedIPS, detectorMeta map[string]any) {
	if !trusted.Valid {
		return
	}
	score := map[int]float64{1: 0.4, 2: 0.7, 3: 1.0}[trusted.Severity]
	event.Tags = appendUniqueString(event.Tags, "ips")
	if score > event.AnomalyScore {
		event.AnomalyScore = score
	}
	detectorMeta["ips"] = map[string]any{"severity": trusted.Severity, "score": score, "dialect": "rest"}
	message := fmt.Sprintf("Firewall intrusion-prevention detection (severity %d).", trusted.Severity)
	if event.ThreatDesc == "" {
		event.ThreatDesc = message
	} else {
		event.ThreatDesc = message + " " + event.ThreatDesc
	}
}

func strictInt(value any) (int, bool) {
	switch value := value.(type) {
	case json.Number:
		parsed, err := strconv.Atoi(value.String())
		return parsed, err == nil
	case float64:
		parsed := int(value)
		return parsed, value == float64(parsed)
	case int:
		return value, true
	default:
		return 0, false
	}
}
