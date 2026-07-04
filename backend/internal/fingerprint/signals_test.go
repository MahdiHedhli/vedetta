package fingerprint

// Spec 004 T3.6: the widened FingerprintSignals entry point must let passive
// signals (services list, TXT-derived model, friendly name) drive risk-category
// detection, matching the classification an equivalent hostname signal produces,
// and preserving the "apply even at lower confidence" behavior.

import (
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestFingerprintSignals_ModelDrivesRiskCategory(t *testing.T) {
	e := NewEngine()

	// Baseline: an equivalent hostname signal triggers the known_exploited category.
	viaHostname := e.Fingerprint(&models.Device{Hostname: "DIR-850L", Vendor: "D-Link"})
	if viaHostname.RiskCategory != "known_exploited" {
		t.Fatalf("hostname path RiskCategory = %q, want known_exploited (test premise)", viaHostname.RiskCategory)
	}

	// Widened: the same evidence arrives only via a TXT-derived model string, with
	// a bare/uninformative hostname. FingerprintSignals must still classify it.
	dev := &models.Device{Hostname: "router", Vendor: "D-Link"}
	viaSignals := e.FingerprintSignals(dev, nil, "DIR-850L Wireless Router", "")
	if viaSignals.RiskCategory != "known_exploited" {
		t.Errorf("signals path RiskCategory = %q, want known_exploited", viaSignals.RiskCategory)
	}
	if !viaSignals.EOLRisk {
		t.Error("signals path should set EOLRisk for the known_exploited EOL model")
	}
	// The device itself must carry the risk flags (applied even if confidence low).
	if dev.RiskCategory != "known_exploited" {
		t.Errorf("device RiskCategory = %q, want known_exploited applied", dev.RiskCategory)
	}
}

func TestFingerprintSignals_ServiceAndFriendlyName(t *testing.T) {
	e := NewEngine()
	dev := &models.Device{Hostname: "cam", Vendor: ""}
	// A friendly name carrying a high-risk camera vendor line.
	res := e.FingerprintSignals(dev, []string{"_rtsp._tcp"}, "", "Foscam Front Door")
	if res.RiskCategory != "high_risk_iot" {
		t.Errorf("RiskCategory = %q, want high_risk_iot from friendly-name vendor line", res.RiskCategory)
	}
}

func TestFingerprintSignals_NoExtraSignals_MatchesFingerprint(t *testing.T) {
	e := NewEngine()
	dev1 := &models.Device{Hostname: "alices-macbook", MACAddress: "00:00:5E:00:53:0A"}
	dev2 := &models.Device{Hostname: "alices-macbook", MACAddress: "00:00:5E:00:53:0A"}
	base := e.Fingerprint(dev1)
	widened := e.FingerprintSignals(dev2, nil, "", "")
	if base.DeviceType != widened.DeviceType || base.RiskCategory != widened.RiskCategory {
		t.Errorf("with no extra signals, FingerprintSignals diverged from Fingerprint: base=%+v widened=%+v", base, widened)
	}
}
