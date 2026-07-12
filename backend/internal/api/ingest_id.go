package api

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/eventid"
	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// deterministicCollectorEventID derives a retry-stable ID without trusting a
// caller-provided source_hash as either raw identity or authentication. Known
// Event fields are normalized explicitly; unknown collector fields remain in a
// canonical metadata object so distinct upstream records remain distinct.
func deterministicCollectorEventID(event models.Event, upstreamEventID string) string {
	metadata := collectorIDMetadata(event.Metadata)
	tags := append([]string(nil), event.Tags...)
	for i := range tags {
		tags[i] = strings.TrimSpace(strings.ToLower(tags[i]))
	}
	sort.Strings(tags)
	tags = compactStrings(tags)

	anomalyScore := event.AnomalyScore
	if anomalyScore < 0 {
		anomalyScore = 0
	} else if anomalyScore > 1 {
		anomalyScore = 1
	}
	segment := strings.TrimSpace(strings.ToLower(event.NetworkSegment))
	if segment == "" {
		segment = "default"
	}
	material := struct {
		UpstreamEventID string         `json:"upstream_event_id"`
		EventType       string         `json:"event_type"`
		SourceIP        string         `json:"source_ip"`
		ServerIP        string         `json:"server_ip"`
		Domain          string         `json:"domain"`
		QueryType       string         `json:"query_type"`
		ResolvedIP      string         `json:"resolved_ip"`
		Blocked         bool           `json:"blocked"`
		AnomalyScore    float64        `json:"anomaly_score"`
		Tags            []string       `json:"tags"`
		Geo             string         `json:"geo"`
		DeviceVendor    string         `json:"device_vendor"`
		NetworkSegment  string         `json:"network_segment"`
		DNSSource       string         `json:"dns_source"`
		ThreatDesc      string         `json:"threat_desc"`
		Metadata        map[string]any `json:"metadata"`
	}{
		UpstreamEventID: strings.TrimSpace(upstreamEventID),
		EventType:       strings.TrimSpace(strings.ToLower(event.EventType)),
		SourceIP:        normalizeAddress(event.SourceIP), ServerIP: normalizeAddress(event.ServerIP),
		Domain: normalizeDNSName(event.Domain), QueryType: strings.ToUpper(strings.TrimSpace(event.QueryType)),
		ResolvedIP: normalizeObservable(event.ResolvedIP), Blocked: event.Blocked,
		AnomalyScore: anomalyScore, Tags: tags,
		Geo: strings.ToUpper(strings.TrimSpace(event.Geo)), DeviceVendor: strings.TrimSpace(event.DeviceVendor),
		NetworkSegment: segment,
		DNSSource:      strings.TrimSpace(strings.ToLower(event.DNSSource)),
		ThreatDesc:     strings.TrimSpace(event.ThreatDesc), Metadata: metadata,
	}

	sourceParts := []string{normalizeAddress(event.SourceIP), strings.TrimSpace(strings.ToLower(event.DNSSource))}
	for _, key := range []string{"gateway", "host", "hostname", "ident", "client"} {
		if value, ok := metadata[key].(string); ok && strings.TrimSpace(value) != "" {
			sourceParts = append(sourceParts, key+"="+strings.TrimSpace(strings.ToLower(value)))
		}
	}
	return eventid.Deterministic("collector", strings.Join(sourceParts, "|"), event.Timestamp, material)
}

// collectorIDMetadata removes values that are either duplicated in the typed
// material, caller-controlled pseudonyms, or added by Core at receipt time.
func collectorIDMetadata(raw string) map[string]any {
	metadata := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &metadata)
	}
	for _, key := range []string{
		"event_id", "timestamp", "event_type", "source_hash", "source_ip", "server_ip",
		"domain", "query_type", "resolved_ip", "blocked", "outcome", "anomaly_score", "tags",
		"geo", "device_vendor", "network_segment", "dns_source", "threat_desc", "metadata",
		"acknowledged", "ack_reason", "device_id", "identity_confidence", "identity_reason",
		"identity_evidence", "origin", "sensor_id", "disposition", "suppression_rule_id",
		"matched_indicator", "match_type", "received_at",
	} {
		delete(metadata, key)
	}
	return metadata
}

func deterministicSensorDNSEventID(sensorID string, upstreamTimestamp time.Time, event models.Event, answers []string, process, direction, responseCode string) string {
	normalizedAnswers := make([]string, 0, len(answers))
	for _, answer := range answers {
		if normalized := normalizeObservable(answer); normalized != "" {
			normalizedAnswers = append(normalizedAnswers, normalized)
		}
	}
	sort.Strings(normalizedAnswers)
	normalizedAnswers = compactStrings(normalizedAnswers)
	material := struct {
		ClientIP   string   `json:"client_ip"`
		ServerIP   string   `json:"server_ip"`
		Domain     string   `json:"domain"`
		QueryType  string   `json:"query_type"`
		ResponseIP string   `json:"response_ip"`
		Blocked    bool     `json:"blocked"`
		Source     string   `json:"source"`
		Answers    []string `json:"answers"`
		Process    string   `json:"process"`
		Direction  string   `json:"direction"`
		RCode      string   `json:"response_code"`
	}{
		ClientIP: normalizeAddress(event.SourceIP), ServerIP: normalizeAddress(event.ServerIP),
		Domain: normalizeDNSName(event.Domain), QueryType: strings.ToUpper(strings.TrimSpace(event.QueryType)),
		ResponseIP: normalizeObservable(event.ResolvedIP), Blocked: event.Blocked,
		Source: strings.TrimSpace(strings.ToLower(event.DNSSource)), Answers: normalizedAnswers,
		Process: strings.TrimSpace(process), Direction: strings.TrimSpace(strings.ToLower(direction)),
		RCode: strings.TrimSpace(strings.ToUpper(responseCode)),
	}
	return eventid.Deterministic("sensor_dns", strings.TrimSpace(sensorID), upstreamTimestamp, material)
}

// deterministicSensorDNSObservationEventID adds the new sensor-generated
// occurrence boundary without changing IDs for legacy sensors that do not send
// one. That compatibility branch prevents an old buffered retry from becoming a
// second row immediately after Core is upgraded.
func deterministicSensorDNSObservationEventID(sensorID string, upstreamTimestamp time.Time, event models.Event, answers []string, process, direction, responseCode, observationID string) string {
	legacyID := deterministicSensorDNSEventID(sensorID, upstreamTimestamp, event, answers, process, direction, responseCode)
	observationID = strings.TrimSpace(observationID)
	if observationID == "" {
		return legacyID
	}
	material := struct {
		ObservationID string `json:"observation_id"`
		EventMaterial string `json:"event_material"`
	}{ObservationID: observationID, EventMaterial: legacyID}
	return eventid.Deterministic("sensor_dns_observation", strings.TrimSpace(sensorID), upstreamTimestamp, material)
}

// parseCollectorTimestamp accepts the timestamp representations Fluent Bit can
// use in its [timestamp, record] pair protocol.
func parseCollectorTimestamp(raw json.RawMessage) time.Time {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(text)); err == nil {
			return parsed.UTC()
		}
		if number, err := strconv.ParseFloat(strings.TrimSpace(text), 64); err == nil {
			return unixFloatTime(number)
		}
	}
	var number float64
	if json.Unmarshal(raw, &number) == nil {
		return unixFloatTime(number)
	}
	var tuple []int64
	if json.Unmarshal(raw, &tuple) == nil && len(tuple) > 0 {
		nanos := int64(0)
		if len(tuple) > 1 {
			nanos = tuple[1]
		}
		return time.Unix(tuple[0], nanos).UTC()
	}
	var object struct {
		Sec  int64 `json:"sec"`
		Nsec int64 `json:"nsec"`
	}
	if json.Unmarshal(raw, &object) == nil && object.Sec != 0 {
		return time.Unix(object.Sec, object.Nsec).UTC()
	}
	return time.Time{}
}

func unixFloatTime(value float64) time.Time {
	seconds := int64(value)
	nanos := int64((value - float64(seconds)) * float64(time.Second))
	return time.Unix(seconds, nanos).UTC()
}

func normalizeDNSName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func normalizeAddress(value string) string {
	value = strings.TrimSpace(value)
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String()
	}
	return strings.ToLower(value)
}

func normalizeObservable(value string) string {
	if parsed := net.ParseIP(strings.TrimSpace(value)); parsed != nil {
		return parsed.String()
	}
	return normalizeDNSName(value)
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	write := 0
	for _, value := range values {
		if value == "" || (write > 0 && values[write-1] == value) {
			continue
		}
		values[write] = value
		write++
	}
	return values[:write]
}
