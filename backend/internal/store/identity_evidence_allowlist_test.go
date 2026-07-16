package store

import "testing"

func TestStoreAllowsSSDPServerTokenEvidence(t *testing.T) {
	if !supportedIdentityEvidenceType("ssdp_server_token") {
		t.Fatal("sensor-accepted SSDP server-token evidence would fail in the identity store")
	}
}
