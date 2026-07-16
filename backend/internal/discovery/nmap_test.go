package discovery

import (
	"testing"
	"time"
)

func TestParseNmapXMLRetainsScanTimeOnHosts(t *testing.T) {
	scanTime := time.Date(2026, 7, 16, 12, 34, 56, 0, time.FixedZone("test", -4*60*60))
	result, err := parseNmapXML([]byte(`<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>`), scanTime, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(result.Hosts))
	}
	if !result.Hosts[0].ObservedAt.Equal(scanTime) || result.Hosts[0].ObservedAt.Location() != time.UTC {
		t.Fatalf("ObservedAt = %s (%s), want %s in UTC", result.Hosts[0].ObservedAt, result.Hosts[0].ObservedAt.Location(), scanTime.UTC())
	}
}
