package threatintel

import (
	"fmt"
	"time"
)

const (
	qtfyAdvisorySource      = "ic3-qtfy-20260826"
	qtfyAdvisoryPublishedAt = "2026-08-26"
	qtfyPresentTTLHours     = 30 * 24
)

// qtfyAdvisoryEntry is an exact, currently relevant indicator published by the
// FBI, NSA, and CNMF in JCSA-20260826-01. It intentionally excludes the
// advisory's historical-only infrastructure and does not turn a parent domain
// into a wildcard match. The agencies recommend investigating or vetting their
// IP indicators before blocking, so these are enrichment and alerting signals,
// never firewall policy.
//
// Source: https://www.ic3.gov/CSA/2026/260826.pdf
type qtfyAdvisoryEntry struct {
	value          string
	kind           string
	firstSeen      string
	lastSeen       string // Source value retained for audit context; not used as a local freshness timestamp.
	classification string
}

var qtfyAdvisoryEntries = []qtfyAdvisoryEntry{
	// QTRouter and the connected proxy-management infrastructure.
	{"anticonstitutionally.sbs", "domain", "2026-03-03", "2027-03-03", "proxy_infrastructure"},
	{"ccgv.me", "domain", "2018-03-12", "2027-03-12", "proxy_infrastructure"},
	{"docker-hub.qt-team.com", "domain", "2022-02-25", "2032-02-25", "proxy_infrastructure"},
	{"fastsecurey.info", "domain", "2026-03-30", "2027-03-31", "proxy_infrastructure"},
	{"instantmessagehub.tech", "domain", "2023-11-03", "2026-11-03", "proxy_infrastructure"},
	{"jump.qt-proxy.org", "domain", "2025-12-14", "2026-12-14", "qtrouter"},
	{"jump.qt-team.com", "domain", "2022-02-25", "2032-02-25", "qtrouter"},
	{"mq-result.qt-proxy.org", "domain", "2025-12-14", "2026-12-14", "qscan"},
	{"mq-result.qt-team.com", "domain", "2022-02-25", "2032-02-25", "qscan"},
	{"mq-task.qt-proxy.org", "domain", "2025-12-14", "2026-12-14", "qscan"},
	{"mq-task.qt-team.com", "domain", "2022-02-25", "2032-02-25", "qscan"},
	{"oraclelabs.biz", "domain", "2025-09-03", "2026-09-03", "proxy_infrastructure"},
	{"qtcyber.com", "domain", "2021-09-02", "2031-09-02", "proxy_infrastructure"},
	{"qt-proxy.org", "domain", "2025-12-14", "2026-12-14", "qscan"},
	{"qtproxy.xyz", "domain", "2022-11-10", "2027-11-10", "qtrouter"},
	{"qt-team.com", "domain", "2022-02-25", "2032-02-25", "qscan"},
	{"securelink.qtproxy.xyz", "domain", "2026-05-29", "Present", "qtrouter"},
	{"wintel.biz", "domain", "2025-09-03", "2026-09-02", "proxy_infrastructure"},
	{"worldswar.online", "domain", "2022-03-02", "2027-03-02", "proxy_infrastructure"},

	{"1.32.216.171", "ipv4", "2026-04-13", "Present", "qtrouter"},
	{"23.95.220.192", "ipv4", "2026-03-12", "Present", "proxy_infrastructure"},
	{"39.104.208.77", "ipv4", "2024-02-28", "Present", "proxy_infrastructure"},
	{"45.202.210.27", "ipv4", "2026-05-29", "Present", "qtrouter"},
	{"206.119.167.207", "ipv4", "2026-01-23", "Present", "proxy_infrastructure"},
	{"154.64.238.222", "ipv4", "2025-06-03", "Present", "qscan"},
	{"154.64.238.247", "ipv4", "2025-05-12", "Present", "qscan"},
	{"27.124.24.220", "ipv4", "2026-08-04", "Present", "qscan_worker"},
	{"27.124.24.237", "ipv4", "2026-08-04", "Present", "qscan_worker"},
	{"45.196.221.138", "ipv4", "2026-08-04", "Present", "qscan_worker"},
	{"134.122.150.22", "ipv4", "2026-08-04", "Present", "qscan_worker"},
	{"134.122.150.25", "ipv4", "2026-08-04", "Present", "qscan_worker"},
}

// LoadQTFYAdvisory imports the current QTFY snapshot from JCSA-20260826-01.
// ReplaceSource ensures upgrades neither accumulate withdrawn entries nor
// overwrite indicators from unrelated sources. The source contains future
// "last seen" values, so all local entries are deliberately anchored to the
// publication date and expire after 30 days unless this reviewed snapshot is
// refreshed in a later release.
func LoadQTFYAdvisory(db *ThreatIntelDB) (int, error) {
	return loadQTFYAdvisoryAt(db)
}

func loadQTFYAdvisoryAt(db *ThreatIntelDB) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("qtfy advisory: threat intel database is required")
	}
	publishedAt, err := time.Parse("2006-01-02", qtfyAdvisoryPublishedAt)
	if err != nil {
		return 0, fmt.Errorf("qtfy advisory: invalid publication date: %w", err)
	}

	indicators := make([]Indicator, 0, len(qtfyAdvisoryEntries))
	for _, entry := range qtfyAdvisoryEntries {
		firstSeen, err := time.Parse("2006-01-02", entry.firstSeen)
		if err != nil {
			return 0, fmt.Errorf("qtfy advisory: %s has invalid first-seen date: %w", entry.value, err)
		}
		indicators = append(indicators, Indicator{
			Value:      entry.value,
			Type:       entry.kind,
			Source:     qtfyAdvisorySource,
			Confidence: 0.90,
			Tags:       []string{"advisory", "qtfy", entry.classification},
			FirstSeen:  firstSeen.UTC(),
			LastSeen:   publishedAt.UTC(),
			TTLHours:   qtfyPresentTTLHours,
		})
	}
	return db.ReplaceSource(qtfyAdvisorySource, indicators)
}
