package dnsintel

import (
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// newFirewallEnricher builds an Enricher with a first-seen tracker and optional
// whitelist / device-lookup hooks for firewall_log tests. All values synthetic.
func newFirewallEnricher() *Enricher {
	e := NewEnricher(nil)
	return e
}

func fwEvent(srcIP, action, direction, dstIP, rule string) *models.Event {
	e := &models.Event{
		EventType:      "firewall_log",
		Timestamp:      time.Now().UTC(),
		SourceIP:       srcIP,
		NetworkSegment: "default",
		Tags:           []string{},
	}
	meta := `{"action":"` + action + `","protocol":"tcp","src_ip":"` + srcIP +
		`","dst_ip":"` + dstIP + `","dst_port":8443,"direction":"` + direction +
		`","rule":"` + rule + `","dialect":"cef"}`
	e.Metadata = meta
	if action == "block" || action == "drop" || action == "reject" {
		e.Blocked = true
	}
	return e
}

func TestEnrichFirewall_FirstSeenScoresHigherThanRecurring(t *testing.T) {
	e := newFirewallEnricher()

	first := fwEvent("192.0.2.45", "block", "out", "203.0.113.10", "IoT_Restrict")
	e.Enrich(first)
	if !hasTag(first.Tags, "new_fw_block") {
		t.Errorf("first-seen block should be tagged new_fw_block; tags=%v", first.Tags)
	}
	if first.AnomalyScore < 0.35 {
		t.Errorf("first-seen block score = %.2f, want ~0.4", first.AnomalyScore)
	}

	// Same (src, dst, rule) again → recurring, lower score, no new_fw_block.
	recurring := fwEvent("192.0.2.45", "block", "out", "203.0.113.10", "IoT_Restrict")
	e.Enrich(recurring)
	if hasTag(recurring.Tags, "new_fw_block") {
		t.Errorf("recurring block must NOT be tagged new_fw_block; tags=%v", recurring.Tags)
	}
	if recurring.AnomalyScore > 0.2 {
		t.Errorf("recurring block score = %.2f, want ~0.1", recurring.AnomalyScore)
	}
	if recurring.AnomalyScore >= first.AnomalyScore {
		t.Errorf("recurring (%.2f) should score lower than first-seen (%.2f)", recurring.AnomalyScore, first.AnomalyScore)
	}
}

func TestEnrichFirewall_RequiredTagsApplied(t *testing.T) {
	e := newFirewallEnricher()
	ev := fwEvent("192.0.2.50", "block", "out", "203.0.113.20", "Rule1")
	e.Enrich(ev)
	for _, want := range []string{"source:unifi", "fw:block", "dir:out"} {
		if !hasTag(ev.Tags, want) {
			t.Errorf("missing required tag %q; tags=%v", want, ev.Tags)
		}
	}
}

func TestEnrichFirewall_WanScanRollupStaysZero(t *testing.T) {
	e := newFirewallEnricher()
	ev := &models.Event{
		EventType:      "firewall_log",
		Timestamp:      time.Now().UTC(),
		Blocked:        true,
		NetworkSegment: "default",
		Tags:           []string{"source:unifi", "fw:drop", "dir:in", "wan_scan_noise"},
		Metadata:       `{"rollup":true,"count":1482,"dialect":"iptables"}`,
	}
	e.Enrich(ev)
	if ev.AnomalyScore != 0.0 {
		t.Errorf("wan_scan_noise rollup score = %.2f, want 0.0", ev.AnomalyScore)
	}
}

func TestEnrichFirewall_WhitelistSuppresses(t *testing.T) {
	e := newFirewallEnricher()
	// Whitelist any event tagged wan_scan_noise (mirrors the seeded default rule).
	e.FirewallWhitelisted = func(tags []string, sourceIP string) (string, bool) {
		for _, tg := range tags {
			if tg == "wan_scan_noise" {
				return "WAN scan noise rollup", true
			}
		}
		return "", false
	}

	ev := &models.Event{
		EventType:      "firewall_log",
		Timestamp:      time.Now().UTC(),
		Blocked:        true,
		NetworkSegment: "default",
		Tags:           []string{"source:unifi", "wan_scan_noise"},
		Metadata:       `{"rollup":true,"count":10,"dialect":"iptables"}`,
	}
	e.Enrich(ev)
	if ev.AnomalyScore != 0.0 {
		t.Errorf("whitelisted event score = %.2f, want 0.0", ev.AnomalyScore)
	}
	if !hasTag(ev.Tags, "whitelisted") {
		t.Errorf("whitelisted event should carry the whitelisted tag; tags=%v", ev.Tags)
	}
}

func TestEnrichFirewall_RiskyDeviceBoost(t *testing.T) {
	e := newFirewallEnricher()
	e.DeviceByIP = func(ip string) *models.Device {
		if ip == "192.0.2.66" {
			return &models.Device{
				IPAddress:    ip,
				Vendor:       "ExampleCam",
				Segment:      "iot",
				RiskCategory: "high_risk_iot",
			}
		}
		return nil
	}

	ev := fwEvent("192.0.2.66", "block", "out", "203.0.113.30", "IoT_Restrict")
	e.Enrich(ev)
	if !hasTag(ev.Tags, "risky_device_fw_block") {
		t.Errorf("risk_category device block should be tagged risky_device_fw_block; tags=%v", ev.Tags)
	}
	// first-seen base 0.4 + 0.3 risk boost = 0.7
	if ev.AnomalyScore < 0.65 {
		t.Errorf("risky-device first-seen block score = %.2f, want >= 0.7", ev.AnomalyScore)
	}
}

func TestEnrichFirewall_IPSSeverityScoring(t *testing.T) {
	cases := []struct {
		sev  int
		want float64
	}{{1, 0.4}, {2, 0.7}, {3, 1.0}}
	for _, c := range cases {
		e := newFirewallEnricher()
		ev := &models.Event{
			EventType:      "firewall_log",
			Timestamp:      time.Now().UTC(),
			Blocked:        true,
			SourceIP:       "203.0.113.77",
			NetworkSegment: "default",
			Tags:           []string{"source:unifi", "ips", "fw:block", "dir:in"},
			Metadata:       `{"action":"block","dialect":"rest","ips_severity":` + itoa(c.sev) + `}`,
		}
		e.Enrich(ev)
		if ev.AnomalyScore != c.want {
			t.Errorf("IPS severity %d score = %.2f, want %.2f", c.sev, ev.AnomalyScore, c.want)
		}
		// MINOR fix: IPS events must carry a non-empty, severity-aware threat_desc.
		if ev.ThreatDesc == "" {
			t.Errorf("IPS severity %d produced empty threat_desc", c.sev)
		}
		if !strings.Contains(ev.ThreatDesc, "IPS") ||
			!strings.Contains(ev.ThreatDesc, "severity "+itoa(c.sev)) {
			t.Errorf("IPS severity %d threat_desc = %q, want it to mention IPS + severity", c.sev, ev.ThreatDesc)
		}
	}
}

// TestEnrichFirewall_IPSThreatDescIncludesSignature verifies the IPS description
// includes the signature/category carried in metadata (msg → rule).
func TestEnrichFirewall_IPSThreatDescIncludesSignature(t *testing.T) {
	e := newFirewallEnricher()
	ev := &models.Event{
		EventType:      "firewall_log",
		Timestamp:      time.Now().UTC(),
		Blocked:        true,
		SourceIP:       "203.0.113.88",
		NetworkSegment: "default",
		Tags:           []string{"source:unifi", "ips", "fw:block", "dir:in"},
		Metadata:       `{"action":"block","dialect":"rest","ips_severity":2,"rule":"ET SCAN probe"}`,
	}
	e.Enrich(ev)
	if !strings.Contains(ev.ThreatDesc, "severity 2") {
		t.Errorf("threat_desc = %q, want it to mention severity 2", ev.ThreatDesc)
	}
	if !strings.Contains(ev.ThreatDesc, "ET SCAN probe") {
		t.Errorf("threat_desc = %q, want it to include the signature 'ET SCAN probe'", ev.ThreatDesc)
	}
}

func TestEnrichFirewall_AllowNotScored(t *testing.T) {
	e := newFirewallEnricher()
	ev := fwEvent("192.0.2.70", "allow", "out", "203.0.113.40", "AllowRule")
	e.Enrich(ev)
	if ev.AnomalyScore != 0.0 {
		t.Errorf("allow event score = %.2f, want 0.0", ev.AnomalyScore)
	}
	if hasTag(ev.Tags, "new_fw_block") {
		t.Error("allow event must not be tagged new_fw_block")
	}
}

func TestEnrichFirewall_DoesNotAffectDNS(t *testing.T) {
	e := newFirewallEnricher()
	dns := &models.Event{
		EventType:      "dns_query",
		Timestamp:      time.Now().UTC(),
		Domain:         "example.com",
		SourceHash:     "h",
		NetworkSegment: "default",
		Tags:           []string{},
	}
	e.Enrich(dns)
	if hasTag(dns.Tags, "source:unifi") || hasTag(dns.Tags, "new_fw_block") {
		t.Errorf("DNS event must not receive firewall tags; tags=%v", dns.Tags)
	}
}

// itoa is a tiny helper to avoid importing strconv just for test metadata.
func itoa(n int) string {
	return string(rune('0' + n))
}
