package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/vedetta-network/vedetta/sensor/internal/iotsecurity"
)

// ErrSecurityUnsupported means Core predates the additive security endpoint.
// Callers stop this delivery stream, while ordinary device/DNS delivery continues.
var ErrSecurityUnsupported = errors.New("Core does not support security observations; upgrade Core")

// PushSecurity delivers immutable observations. The caller owns batching and
// retains observation IDs until this method confirms every record was accepted.
func (c *CoreClient) PushSecurity(ctx context.Context, observations []iotsecurity.Observation) error {
	if len(observations) == 0 {
		return nil
	}
	if len(observations) > 32 {
		return errors.New("security batch exceeds 32 observations")
	}
	payload := struct {
		SensorID     string                    `json:"sensor_id"`
		Observations []iotsecurity.Observation `json:"observations"`
	}{SensorID: c.SensorID, Observations: observations}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode security observations: %w", err)
	}
	if len(encoded) > 256<<10 {
		return errors.New("security batch exceeds 256 KiB")
	}
	var response struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
		Failed     int `json:"failed"`
	}
	status, err := c.doJSONStatus(ctx, http.MethodPost, "/api/v1/sensor/security", payload, &response, false)
	if status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		return ErrSecurityUnsupported
	}
	if err != nil {
		return err
	}
	if response.Failed != 0 || response.Accepted < 0 || response.Duplicates < 0 || response.Accepted+response.Duplicates != len(observations) {
		return fmt.Errorf("security delivery incomplete: accepted=%d duplicates=%d failed=%d sent=%d", response.Accepted, response.Duplicates, response.Failed, len(observations))
	}
	return nil
}
