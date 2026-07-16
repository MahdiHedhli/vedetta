package api

import "testing"

func TestSensorIdentityEvidenceAllowsSSDPServerToken(t *testing.T) {
	if !sensorIdentityEvidenceType("ssdp_server_token") {
		t.Fatal("passive SSDP server-token evidence would be discarded at sensor ingestion")
	}
	if operatorIdentityEvidenceType("ssdp_server_token") {
		t.Fatal("descriptive SSDP server tokens must not become operator identity evidence")
	}
}
