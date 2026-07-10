package transmit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Known-vector test shared in spirit with specs/003-threat-network's validator.
// Fixed secret / timestamp / nonce / body → deterministic signature.
func TestSignKnownVector(t *testing.T) {
	secret := []byte("reporter-secret-example")
	body := []byte(`{"schema_version":1,"batch_id":"b"}`)
	ts := "1751551200"
	nonce := "00000000-0000-4000-8000-000000000000"

	// Recompute the expected value independently.
	sum := sha256.Sum256(body)
	canonical := ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(canonical))
	want := hex.EncodeToString(m.Sum(nil))

	got := Sign(secret, SignatureInput{Timestamp: ts, Nonce: nonce, Body: body})
	if got != want {
		t.Errorf("Sign = %s, want %s", got, want)
	}
}

func TestCanonicalStringShape(t *testing.T) {
	in := SignatureInput{Timestamp: "123", Nonce: "n", Body: []byte("x")}
	sum := sha256.Sum256([]byte("x"))
	want := "123\nn\n" + hex.EncodeToString(sum[:])
	if got := CanonicalString(in); got != want {
		t.Errorf("canonical = %q, want %q", got, want)
	}
}

// Signature is deterministic and stable for identical inputs.
func TestSignDeterministic(t *testing.T) {
	secret := []byte("s")
	in := SignatureInput{Timestamp: "1", Nonce: "n", Body: []byte("body")}
	a := Sign(secret, in)
	b := Sign(secret, in)
	if a != b {
		t.Errorf("signature not deterministic: %q != %q", a, b)
	}
}

// TestClientSignatureMatchesServerVerification pins the client's signing key to
// what the threat network actually verifies (beta-gate C1). The server stores
// only hex(sha256(secret)) and verifies HMAC keyed on that hash; signing with the
// RAW secret made every upload fail. This reproduces the server's math
// independently (no fixture dependency) and asserts the client matches — and that
// the old raw-secret signature does NOT, guarding against regression.
func TestClientSignatureMatchesServerVerification(t *testing.T) {
	const rawSecret = "reporter-secret-example"
	in := SignatureInput{
		Timestamp: "1751551200",
		Nonce:     "00000000-0000-4000-8000-000000000000",
		Body:      []byte(`{"schema_version":1,"batch_id":"b"}`),
	}

	// Server side: key = hex(sha256(secret)); expected = hex(HMAC(key, canonical)).
	keyHash := sha256.Sum256([]byte(rawSecret))
	serverKey := hex.EncodeToString(keyHash[:])
	bodyHash := sha256.Sum256(in.Body)
	canonical := in.Timestamp + "\n" + in.Nonce + "\n" + hex.EncodeToString(bodyHash[:])
	m := hmac.New(sha256.New, []byte(serverKey))
	m.Write([]byte(canonical))
	serverExpects := hex.EncodeToString(m.Sum(nil))

	if clientSends := Sign([]byte(SigningKey(rawSecret)), in); clientSends != serverExpects {
		t.Fatalf("client signature does not match server verification:\n client %s\n server %s", clientSends, serverExpects)
	}
	if raw := Sign([]byte(rawSecret), in); raw == serverExpects {
		t.Fatal("raw-secret signature unexpectedly matched server — the guard is ineffective")
	}
}
