package processing

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// StoreIdentityResolver is the canonical Processor adapter for Core's
// timestamp-aware device resolver.
type StoreIdentityResolver struct {
	DB *store.DB
}

func (resolver StoreIdentityResolver) ResolveEventIdentity(ctx context.Context, event models.Event, in IdentityContext) (IdentityResolution, error) {
	if resolver.DB == nil {
		return IdentityResolution{Reason: "unresolved", Evidence: json.RawMessage(`{"reason":"unresolved"}`)}, nil
	}
	metadata := decodeObject(event.Metadata)
	evidence := []store.DeviceIdentityEvidenceInput{}
	// Stable identity values are accepted only with authenticated sensor context.
	// Generic collector metadata must not be able to claim another device.
	if strings.TrimSpace(in.SensorID) != "" {
		evidence = append(evidence, identityEvidence(metadata["identity_evidence"])...)
		evidence = append(evidence, identityEvidence(in.SourceMeta["identity_evidence"])...)
	}
	macAddress := ""
	if strings.TrimSpace(in.SensorID) != "" {
		macAddress = firstString(metadata, "mac_address", "mac")
		if macAddress == "" {
			macAddress = firstString(in.SourceMeta, "mac_address", "mac")
		}
	}
	resolved, err := resolver.DB.ResolveDeviceAt(ctx, store.DeviceIdentityResolutionRequest{
		Timestamp: event.Timestamp, IPAddress: event.SourceIP, MACAddress: macAddress,
		Segment: event.NetworkSegment, SensorID: in.SensorID, Evidence: evidence,
	})
	if err != nil {
		return IdentityResolution{}, err
	}
	return IdentityResolution{
		DeviceID: resolved.DeviceID, Confidence: resolved.Confidence, Reason: resolved.Reason,
		Evidence: json.RawMessage(resolved.Evidence),
	}, nil
}

func identityEvidence(value any) []store.DeviceIdentityEvidenceInput {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return nil
	}
	if len(values) > 32 {
		values = values[:32]
	}
	out := make([]store.DeviceIdentityEvidenceInput, 0, len(values))
	for _, raw := range values {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := item["type"].(string)
		identifier, _ := item["value"].(string)
		kind = strings.ToLower(strings.TrimSpace(kind))
		identifier = strings.TrimSpace(identifier)
		if !allowedIdentityEvidenceType(kind) || identifier == "" || len(identifier) > 512 {
			continue
		}
		confidence := floatFromMap(item, "confidence", 0)
		source, _ := item["source"].(string)
		display, _ := item["display_value"].(string)
		sensitive, _ := item["sensitive"].(bool)
		out = append(out, store.DeviceIdentityEvidenceInput{
			Type: kind, Value: identifier, Source: strings.TrimSpace(source),
			Confidence: clampScore(confidence), Sensitive: sensitive, DisplayValue: strings.TrimSpace(display),
		})
	}
	return out
}

func allowedIdentityEvidenceType(kind string) bool {
	switch kind {
	case "dhcp_client_id", "dhcp_option_55", "ssdp_uuid", "ssdp_device_type",
		"mdns_name", "mdns_service", "mdns_txt_model", "mdns_txt_vendor", "mdns_txt_id",
		"ssdp_server_token", "hostname", "mac":
		return true
	default:
		return false
	}
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
