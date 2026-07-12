package processing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
	"golang.org/x/net/publicsuffix"
)

type threatLookupCandidate struct {
	observable  models.Observable
	lookupValue string
	matchScope  string
}

func threatIntelEvidence(lookup ThreatLookup, event models.Event, observables []models.Observable, now time.Time) []models.DetectionEvidence {
	if lookup == nil {
		return nil
	}
	out := make([]models.DetectionEvidence, 0, len(observables))
	for _, observable := range observables {
		switch observable.Type {
		case ObservableDomain, ObservableCNAME, ObservableDestinationIP, ObservableURL:
		default:
			continue
		}
		for _, candidate := range threatLookupCandidates(observable) {
			results := []threatintel.LookupResult{lookup.Lookup(candidate.lookupValue)}
			if multi, ok := lookup.(ThreatLookupAll); ok {
				results = multi.LookupAll(candidate.lookupValue)
			}
			for _, result := range results {
				if !result.Found || result.Indicator == nil {
					continue
				}
				if candidate.matchScope == "etld_plus_one" && !hasIndicatorTag(result.Indicator.Tags, "indicator_scope:etld_plus_one") {
					continue
				}
				freshness := result.Indicator.LastSeen.UTC()
				details, _ := json.Marshal(map[string]any{
					"indicator_type":    result.Indicator.Type,
					"feed_tags":         append([]string(nil), result.Indicator.Tags...),
					"first_seen":        result.Indicator.FirstSeen.UTC(),
					"ttl_hours":         result.Indicator.TTLHours,
					"matched_indicator": candidate.lookupValue,
					"match_scope":       candidate.matchScope,
				})
				out = append(out, models.DetectionEvidence{
					EvidenceID:        uuid.NewString(),
					EventID:           event.EventID,
					Detector:          "threat_intelligence",
					Category:          threatCategory(result.Indicator.Tags),
					ObservableType:    candidate.observable.Type,
					ObservableValue:   candidate.observable.Value,
					ThreatSource:      result.Indicator.Source,
					SourceConfidence:  clampScore(result.Confidence),
					FeedFreshness:     &freshness,
					FeedStale:         result.IsStale,
					Rationale:         fmt.Sprintf("%s matched threat intelligence source %s", candidate.observable.Value, result.Indicator.Source),
					ScoreContribution: clampScore(result.Confidence),
					Outcome:           eventOutcome(event),
					Details:           details,
					CreatedAt:         now,
				})
			}
		}
	}
	return deduplicateEvidence(out)
}

func threatLookupCandidates(observable models.Observable) []threatLookupCandidate {
	candidates := []threatLookupCandidate{{observable: observable, lookupValue: observable.Value, matchScope: "exact"}}
	host := ""
	switch observable.Type {
	case ObservableDomain, ObservableCNAME:
		host = observable.Value
	case ObservableURL:
		if parsed, err := url.Parse(observable.Value); err == nil {
			host = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		}
	}
	if host == "" {
		return candidates
	}
	if host != observable.Value {
		candidates = append(candidates, threatLookupCandidate{observable: observable, lookupValue: host, matchScope: "host"})
	}
	if registered, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && registered != "" && registered != host {
		candidates = append(candidates, threatLookupCandidate{observable: observable, lookupValue: registered, matchScope: "etld_plus_one"})
	}
	return candidates
}

func hasIndicatorTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func heuristicEvidence(event models.Event, detectorMeta map[string]any, now time.Time) []models.DetectionEvidence {
	definitions := []struct {
		Tags       []string
		Detector   string
		Category   string
		MetaKey    string
		Default    float64
		Observable models.Observable
	}{
		{[]string{"dga_candidate", "dga"}, "dga", "command_and_control", "dga", 0.30, primaryDomainObservable(event)},
		{[]string{"dns_tunnel", "dns_tunneling", "tunneling_candidate"}, "dns_tunnel", "exfiltration", "tunnel", 0.30, primaryDomainObservable(event)},
		{[]string{"beaconing", "beaconing_candidate"}, "beaconing", "command_and_control", "beacon", 0.30, primaryDomainObservable(event)},
		{[]string{"dns_rebinding"}, "dns_rebinding", "network_attack", "rebinding", 0.40, primaryDomainObservable(event)},
		{[]string{"dns_bypass"}, "dns_bypass", "defense_evasion", "bypass", 0.50, primaryDomainObservable(event)},
		{[]string{"ips"}, "ips", "intrusion_prevention", "ips", 0.70, primaryDestinationObservable(event)},
		{[]string{"new_fw_block"}, "firewall_first_seen", "network_activity", "firewall", 0.40, primaryDestinationObservable(event)},
	}

	out := []models.DetectionEvidence{}
	for _, definition := range definitions {
		if definition.Observable.Value == "" {
			continue
		}
		details := mapValue(detectorMeta[definition.MetaKey])
		if len(details) == 0 || !hasAnyTag(event.Tags, definition.Tags...) {
			continue
		}
		score := scoreFromMeta(details, definition.Default)
		if definition.Detector == "ips" && event.AnomalyScore > score {
			score = event.AnomalyScore
		}
		if definition.Detector == "firewall_first_seen" && event.AnomalyScore > score {
			score = event.AnomalyScore
		}
		detailJSON, _ := json.Marshal(details)
		out = append(out, models.DetectionEvidence{
			EvidenceID:        uuid.NewString(),
			EventID:           event.EventID,
			Detector:          definition.Detector,
			Category:          definition.Category,
			ObservableType:    definition.Observable.Type,
			ObservableValue:   definition.Observable.Value,
			SourceConfidence:  clampScore(score),
			Rationale:         detectorRationale(definition.Detector, event),
			ScoreContribution: clampScore(score),
			Outcome:           eventOutcome(event),
			Details:           detailJSON,
			CreatedAt:         now,
		})
	}

	// Compatibility path: when a custom Enricher produced threat_db metadata but
	// no explicit ThreatLookup was configured, retain its Core-owned provenance.
	if hasAnyTag(event.Tags, "known_bad") {
		if meta := mapValue(detectorMeta["threat_db"]); len(meta) > 0 {
			indicator := stringFromMap(meta, "indicator")
			if indicator == "" {
				indicator = event.MatchedIndicator
			}
			kind := event.MatchType
			if kind == "resolved_ip" {
				kind = ObservableDestinationIP
			}
			if kind == "" {
				kind = ObservableDomain
			}
			if indicator != "" {
				score := floatFromMap(meta, "confidence", event.AnomalyScore)
				detailJSON, _ := json.Marshal(meta)
				out = append(out, models.DetectionEvidence{
					EvidenceID:        uuid.NewString(),
					EventID:           event.EventID,
					Detector:          "threat_intelligence",
					Category:          "known_malicious",
					ObservableType:    kind,
					ObservableValue:   normalizeObservable(kind, indicator),
					ThreatSource:      stringFromMap(meta, "source"),
					SourceConfidence:  clampScore(score),
					Rationale:         event.ThreatDesc,
					ScoreContribution: clampScore(score),
					Outcome:           eventOutcome(event),
					Details:           detailJSON,
					CreatedAt:         now,
				})
			}
		}
	}
	return deduplicateEvidence(out)
}

// stripThreatEvidenceTags prevents a feed's descriptive tags/reasons from being
// reinterpreted as output from Core's deterministic detectors. Genuine detector
// results remain available in the Core-owned `detections` metadata namespace.
func stripThreatEvidenceTags(event *models.Event, evidence []models.DetectionEvidence) {
	for _, item := range evidence {
		if item.Detector == "threat_intelligence" {
			event.Tags = removeExactTags(event.Tags, evidenceFeedTags(item)...)
		}
	}
}

func markFindingEligibility(evidence []models.DetectionEvidence) {
	for i := range evidence {
		// Community matches and first-seen firewall observations are supporting
		// evidence only. When another detector creates a finding, the event link
		// makes these records visible without letting them drive priority.
		if isCommunitySource(evidence[i].ThreatSource) || evidence[i].Detector == "firewall_first_seen" {
			evidence[i].CreatesFinding = false
			continue
		}
		evidence[i].CreatesFinding = evidence[i].Detector == "ips" || evidence[i].ScoreContribution >= 0.30
	}
}

func findingCandidates(event models.Event, identity IdentityResolution, envelope IngressEnvelope, evidence []models.DetectionEvidence, suppression SuppressionDecision) []models.FindingCandidate {
	identityKey, fallback := findingIdentity(event, identity, envelope)
	byKey := make(map[string]*models.FindingCandidate)
	order := []string{}
	for _, item := range evidence {
		if !item.CreatesFinding || item.ObservableValue == "" {
			continue
		}
		key := makeFindingKey(identityKey, item.Detector, item.ObservableType, item.ObservableValue)
		disposition := models.DispositionActive
		suppressionRuleID := ""
		if suppression.Suppressed {
			disposition = models.DispositionSuppressed
			suppressionRuleID = suppression.RuleID
		} else if match, ok := suppression.Evidence[item.EvidenceID]; ok {
			disposition = models.DispositionSuppressed
			suppressionRuleID = match.RuleID
		}
		candidate := byKey[key]
		if candidate == nil {
			candidate = &models.FindingCandidate{
				FindingKey:            key,
				DeviceID:              identity.DeviceID,
				FallbackIdentity:      fallback,
				Detector:              item.Detector,
				Category:              item.Category,
				PrimaryObservableType: item.ObservableType,
				PrimaryObservable:     item.ObservableValue,
				ObservedAt:            event.Timestamp,
				Score:                 item.ScoreContribution,
				Priority:              priority(item.ScoreContribution),
				Blocked:               event.Blocked,
				Outcome:               eventOutcome(event),
				Reason:                item.Rationale,
				RecommendedAction:     recommendedAction(item),
				Disposition:           disposition,
				SuppressionRuleID:     suppressionRuleID,
				EvidenceIDs:           []string{item.EvidenceID},
			}
			byKey[key] = candidate
			order = append(order, key)
			continue
		}
		candidate.EvidenceIDs = append(candidate.EvidenceIDs, item.EvidenceID)
		// A finding stays actionable if any independent evidence for its stable
		// key is not covered by the typed suppression policy.
		if candidate.Disposition == models.DispositionSuppressed && disposition == models.DispositionActive {
			candidate.Disposition = models.DispositionActive
			candidate.SuppressionRuleID = ""
		}
		if item.ScoreContribution > candidate.Score {
			candidate.Score = item.ScoreContribution
			candidate.Priority = priority(item.ScoreContribution)
			candidate.Reason = item.Rationale
			candidate.RecommendedAction = recommendedAction(item)
		}
	}
	out := make([]models.FindingCandidate, 0, len(order))
	for _, key := range order {
		candidate := byKey[key]
		// Corroborating/advisory evidence belongs only when it describes the same
		// observed value. This retains community/first-seen context without leaking
		// an unrelated detector from a multi-finding event into the explanation.
		for _, item := range evidence {
			if item.CreatesFinding || item.ObservableType != candidate.PrimaryObservableType || item.ObservableValue != candidate.PrimaryObservable {
				continue
			}
			candidate.EvidenceIDs = appendUniqueString(candidate.EvidenceIDs, item.EvidenceID)
		}
		out = append(out, *candidate)
	}
	return out
}

func findingIdentity(event models.Event, identity IdentityResolution, envelope IngressEnvelope) (keyMaterial, fallback string) {
	if identity.DeviceID != "" {
		return "device:" + identity.DeviceID, ""
	}
	segment := event.NetworkSegment
	if segment == "" {
		segment = "default"
	}
	sourceHash := strings.TrimSpace(event.SourceHash)
	if sourceHash == "" || sourceHash == "unknown" {
		// Avoid attaching unrelated unresolved devices to one global "unknown"
		// finding. Such records intentionally do not aggregate until identified.
		fallback = "event:" + event.EventID
	} else {
		material := sourceHash + "\x00" + envelope.SensorID + "\x00" + segment
		sum := sha256.Sum256([]byte(material))
		fallback = "source:" + hex.EncodeToString(sum[:])
	}
	return "unresolved:" + fallback, fallback
}

func makeFindingKey(identity, detector, observableType, observable string) string {
	material := strings.Join([]string{identity, detector, observableType, normalizeObservable(observableType, observable)}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func finalizeEventVerdict(event *models.Event, evidence []models.DetectionEvidence) {
	event.Tags = removeExactTags(event.Tags, "known_bad", "community_advisory")
	for _, item := range evidence {
		if item.Detector == "threat_intelligence" {
			event.Tags = removeExactTags(event.Tags, evidenceFeedTags(item)...)
		}
	}
	event.AnomalyScore = 0
	event.MatchType = ""
	event.MatchedIndicator = ""
	best := -1.0
	communityConfidence := 0.0
	supportingScore := 0.0
	hasActionable := false
	hasCommunity := false
	for _, item := range evidence {
		if item.Detector == "threat_intelligence" && isCommunitySource(item.ThreatSource) {
			hasCommunity = true
			if item.SourceConfidence > communityConfidence {
				communityConfidence = item.SourceConfidence
			}
			continue
		}
		if item.Detector == "firewall_first_seen" {
			// First-seen is corroboration/context, never malicious by itself.
			if item.ScoreContribution > supportingScore {
				supportingScore = item.ScoreContribution
			}
			continue
		}
		hasActionable = true
		if item.ScoreContribution > event.AnomalyScore {
			event.AnomalyScore = item.ScoreContribution
		}
		if item.Detector != "threat_intelligence" {
			continue
		}
		event.Tags = appendUniqueString(event.Tags, "known_bad")
		for _, tag := range evidenceFeedTags(item) {
			event.Tags = appendUniqueString(event.Tags, tag)
		}
		// The legacy fields can represent one match only. Prefer a domain match;
		// every other match still exists independently in typed evidence.
		prefer := item.ObservableType == ObservableDomain && event.MatchType != "domain"
		if event.MatchedIndicator == "" || prefer || (event.MatchType != "domain" && item.ScoreContribution > best) {
			event.MatchedIndicator = item.ObservableValue
			if item.ObservableType == ObservableDestinationIP {
				event.MatchType = "resolved_ip"
			} else {
				event.MatchType = "domain"
			}
			best = item.ScoreContribution
		}
	}
	if hasCommunity {
		event.Tags = appendUniqueString(event.Tags, "community_advisory")
	}
	if !hasActionable && hasCommunity {
		// Keep community-only events visible in raw evidence below the actionable
		// threshold. The original source confidence remains in typed evidence.
		event.AnomalyScore = math.Min(0.20, communityConfidence)
		event.ThreatDesc = "Community-feed match (advisory only); no independent local or trusted-feed detector corroborated it."
	} else if !hasActionable && supportingScore > event.AnomalyScore {
		// Preserve the legacy raw-event SNR signal while keeping it out of the
		// findings abstraction unless a substantive detector corroborates it.
		event.AnomalyScore = supportingScore
	}
}

func evidenceFeedTags(evidence models.DetectionEvidence) []string {
	var details struct {
		FeedTags []string `json:"feed_tags"`
	}
	if len(evidence.Details) > 0 {
		_ = json.Unmarshal(evidence.Details, &details)
	}
	out := details.FeedTags[:0]
	for _, tag := range details.FeedTags {
		if !strings.HasPrefix(tag, "indicator_scope:") {
			out = append(out, tag)
		}
	}
	return out
}

func removeExactTags(tags []string, drop ...string) []string {
	if len(tags) == 0 || len(drop) == 0 {
		return tags
	}
	dropped := make(map[string]struct{}, len(drop))
	for _, tag := range drop {
		dropped[tag] = struct{}{}
	}
	out := tags[:0]
	for _, tag := range tags {
		if _, remove := dropped[tag]; !remove {
			out = append(out, tag)
		}
	}
	return out
}

func deduplicateEvidence(values []models.DetectionEvidence) []models.DetectionEvidence {
	seen := make(map[string]int, len(values))
	out := make([]models.DetectionEvidence, 0, len(values))
	for _, value := range values {
		key := strings.Join([]string{value.Detector, value.ObservableType, value.ObservableValue, value.ThreatSource}, "\x00")
		if index, ok := seen[key]; ok {
			if value.ScoreContribution > out[index].ScoreContribution {
				out[index] = value
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, value)
	}
	return out
}

func priority(score float64) models.Priority {
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

func recommendedAction(evidence models.DetectionEvidence) string {
	// Enforcement outcome belongs to the durable finding aggregate, not one
	// supporting event. Keeping the action outcome-neutral prevents a later
	// allowed event from producing a "mixed" finding with blocked-only advice.
	switch evidence.Detector {
	case "threat_intelligence", "ips":
		return "Isolate the affected device, verify its software or firmware, and investigate related activity."
	case "dns_tunnel":
		return "Inspect the device for data exfiltration and restrict unexpected DNS traffic."
	case "dns_rebinding":
		return "Block the domain and inspect the target device and browser for unauthorized access."
	case "dga", "beaconing":
		return "Inspect the device for malware and review repeated connections to this destination."
	case "dns_bypass":
		return "Confirm whether the device is permitted to bypass the local resolver and restrict it if not."
	default:
		return "Review the supporting events and confirm whether this activity is expected."
	}
}

func threatCategory(tags []string) string {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "c2", "command_and_control", "botnet":
			return "command_and_control"
		case "phishing":
			return "phishing"
		case "malware", "malware_distribution":
			return "malware"
		}
	}
	return "known_malicious"
}

func primaryDomainObservable(event models.Event) models.Observable {
	return models.Observable{Type: ObservableDomain, Value: normalizeObservable(ObservableDomain, event.Domain)}
}

func primaryDestinationObservable(event models.Event) models.Observable {
	for _, observable := range ExtractObservables(event) {
		if observable.Type == ObservableDestinationIP {
			return observable
		}
	}
	if event.Domain != "" {
		return primaryDomainObservable(event)
	}
	return models.Observable{}
}

func detectorRationale(detector string, event models.Event) string {
	if strings.TrimSpace(event.ThreatDesc) != "" {
		return event.ThreatDesc
	}
	switch detector {
	case "dga":
		return "The domain has deterministic characteristics associated with domain-generation algorithms."
	case "dns_tunnel":
		return "The DNS query has deterministic characteristics associated with DNS tunneling."
	case "beaconing":
		return "Repeated activity follows a consistent beacon-like interval."
	case "dns_rebinding":
		return "The domain changed from a public to a private destination."
	case "dns_bypass":
		return "The device appears to bypass the configured local resolver."
	case "ips":
		return "The firewall intrusion-prevention engine reported this activity."
	default:
		return "The event met a deterministic detection rule."
	}
}

func scoreFromMeta(meta map[string]any, fallback float64) float64 {
	return clampScore(floatFromMap(meta, "score", fallback))
}

func floatFromMap(meta map[string]any, key string, fallback float64) float64 {
	value, ok := meta[key]
	if !ok {
		return fallback
	}
	switch value := value.(type) {
	case float64:
		return value
	case json.Number:
		if parsed, err := value.Float64(); err == nil {
			return parsed
		}
	}
	return fallback
}

func stringFromMap(meta map[string]any, key string) string {
	value, _ := meta[key].(string)
	return value
}

func mapValue(value any) map[string]any {
	valueMap, _ := value.(map[string]any)
	if valueMap == nil {
		return map[string]any{}
	}
	return valueMap
}

func clampScore(value float64) float64 {
	return math.Max(0, math.Min(1, value))
}

func hasAnyTag(tags []string, expected ...string) bool {
	for _, tag := range tags {
		for _, candidate := range expected {
			if tag == candidate {
				return true
			}
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func eventOutcome(event models.Event) string {
	switch event.Outcome {
	case "blocked", "allowed", "observed":
		return event.Outcome
	default:
		if event.Blocked {
			return "blocked"
		}
		return "observed"
	}
}

func isCommunitySource(source string) bool {
	source = strings.ToLower(source)
	return strings.Contains(source, "community") || strings.Contains(source, "vedetta")
}
