package processing

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

type StoreDeviceContextResolver struct {
	DB *store.DB
}

func (resolver StoreDeviceContextResolver) ResolveDeviceContext(ctx context.Context, deviceID string, observedAt time.Time) (DeviceContext, error) {
	if resolver.DB == nil || strings.TrimSpace(deviceID) == "" {
		return DeviceContext{}, nil
	}
	device, err := resolver.DB.GetDeviceByID(ctx, deviceID)
	if err != nil || device == nil {
		return DeviceContext{}, err
	}
	result := DeviceContext{
		DeviceID: device.DeviceID, Vendor: device.Vendor, DeviceType: device.DeviceType,
		Model: device.Model, Segment: device.Segment, RiskCategory: device.RiskCategory,
		RiskModel: device.RiskModel, EOLRisk: device.EOLRisk, FirstSeen: device.FirstSeen,
		IdentityConfidence: device.IdentityConfidence, IdentityStatus: device.IdentityStatus,
	}
	age := observedAt.UTC().Sub(device.FirstSeen.UTC())
	if !device.FirstSeen.IsZero() && age >= 0 {
		result.IsNew = age < 48*time.Hour
		result.IsVeryNew = age < time.Hour
	}
	return result, nil
}

func applyDeviceContext(event *models.Event, context DeviceContext) {
	// Caller-provided context was removed during sanitization. Only a context
	// loaded through the stable resolved device can populate these fields/tags.
	event.DeviceVendor = context.Vendor
	// NetworkSegment is observed event-time context. The device projection is its
	// current segment and belongs only in typed DeviceContext; overwriting here
	// would rewrite delayed historical events after a VLAN move.
	if context.IsNew {
		event.Tags = appendUniqueString(event.Tags, "new_device")
	}
	if context.IsVeryNew {
		event.Tags = appendUniqueString(event.Tags, "very_new_device")
	}
	risk := context.RiskCategory
	if risk == "" && context.EOLRisk {
		risk = "eol_eos"
	}
	switch risk {
	case "eol_eos":
		event.Tags = appendUniqueString(event.Tags, "eol_router")
	case "high_risk_iot":
		event.Tags = appendUniqueString(event.Tags, "high_risk_iot")
	case "known_exploited":
		event.Tags = appendUniqueString(event.Tags, "known_exploited")
	}
}

func applyPostDetectionContext(event *models.Event, context DeviceContext, evidence []models.DetectionEvidence) {
	maxScore := 0.0
	for _, item := range evidence {
		if item.ScoreContribution > maxScore && !isCommunitySource(item.ThreatSource) {
			maxScore = item.ScoreContribution
		}
	}
	if maxScore <= 0 {
		return
	}
	if (context.Segment == "iot" || context.Segment == "guest") && maxScore >= 0.30 {
		event.Tags = appendUniqueString(event.Tags, "iot_context")
	}
	if context.IsNew && maxScore >= 0.30 {
		event.Tags = appendUniqueString(event.Tags, "new_device_context")
	}
	if (context.EOLRisk || context.RiskCategory == "eol_eos" || context.RiskCategory == "known_exploited") && maxScore >= 0.30 {
		event.Tags = appendUniqueString(event.Tags, "eol_device_context")
	}
}

func attachDeviceContext(evidence []models.DetectionEvidence, context DeviceContext) {
	data, err := json.Marshal(context)
	if err != nil {
		data = []byte("{}")
	}
	for i := range evidence {
		evidence[i].DeviceContext = append(json.RawMessage(nil), data...)
	}
}
