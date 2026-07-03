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
	if Sign(secret, in) != Sign(secret, in) {
		t.Errorf("signature not deterministic")
	}
}
