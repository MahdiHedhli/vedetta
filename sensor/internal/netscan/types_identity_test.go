package netscan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoveredHostIdentityEvidenceWireShape(t *testing.T) {
	host := DiscoveredHost{
		IPAddress: "192.0.2.53", Status: "up",
		IdentityEvidence: []IdentityEvidence{{
			Type: "dhcp_client_id", Value: "0100005e005335", Source: "passive_dhcp",
			Confidence: 0.95, Sensitive: true,
		}},
	}
	encoded, err := json.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"identity_evidence"`, `"type":"dhcp_client_id"`,
		`"source":"passive_dhcp"`, `"sensitive":true`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("wire JSON missing %s: %s", field, encoded)
		}
	}
}
