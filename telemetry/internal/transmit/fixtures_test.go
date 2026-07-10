package transmit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The signature construction must match the shared vector fixture consumed by
// specs/003-threat-network's validator tests. If this breaks, the two services
// have diverged on the auth contract.
func TestSharedSignatureVector(t *testing.T) {
	path := filepath.Join("..", "..", "..", "specs", "002-telemetry-service", "contracts", "fixtures", "signature-vector.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("signature vector fixture not found: %v", err)
	}
	var v struct {
		ReporterSecret    string `json:"reporter_secret"`
		Timestamp         string `json:"timestamp"`
		Nonce             string `json:"nonce"`
		Body              string `json:"body"`
		ExpectedSignature string `json:"expected_signature"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	got := Sign([]byte(SigningKey(v.ReporterSecret)), SignatureInput{
		Timestamp: v.Timestamp, Nonce: v.Nonce, Body: []byte(v.Body),
	})
	if got != v.ExpectedSignature {
		t.Errorf("signature vector mismatch:\n got %s\nwant %s", got, v.ExpectedSignature)
	}
}
