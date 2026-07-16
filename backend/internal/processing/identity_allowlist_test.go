package processing

import "testing"

func TestEventIdentityEvidenceAllowsSSDPServerToken(t *testing.T) {
	if !allowedIdentityEvidenceType("ssdp_server_token") {
		t.Fatal("authenticated sensor event metadata would discard SSDP server-token evidence")
	}
}
