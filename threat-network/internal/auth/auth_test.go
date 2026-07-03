package auth

import (
	"strconv"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

func newAuth(t *testing.T, now time.Time) (*Authenticator, *store.DB) {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	a := &Authenticator{DB: db, Now: func() time.Time { return now }}
	return a, db
}

// registerReporter creates a reporter and returns its id and signing key.
func registerReporter(t *testing.T, db *store.DB) (id, signingKey string) {
	t.Helper()
	resp, err := Register(db, RegisterRequest{
		SchemaVersion: 1, InstallID: "11111111-1111-4111-8111-111111111111",
		VedettaVersion: "0.1.0", Capabilities: []string{"known_bad_domain_hit"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return resp.ReporterID, SigningKeyForSecret(resp.ReporterSecret)
}

func signed(id, key string, now time.Time, nonce string, body []byte) SignedRequest {
	tsStr := strconv.FormatInt(now.Unix(), 10)
	sig := ComputeSignature(key, tsStr, nonce, body)
	return SignedRequest{ReporterID: id, Timestamp: tsStr, Nonce: nonce, Signature: sig, Body: body}
}

func TestValidSignaturePasses(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed(id, key, now, "nonce-1", body)
	r, err := a.Verify(req)
	if err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	if r.ReporterID != id {
		t.Fatalf("reporter mismatch")
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	req := signed(id, key, now, "nonce-1", []byte(`{"batch_id":"b1"}`))
	req.Body = []byte(`{"batch_id":"TAMPERED"}`) // signature no longer matches
	_, err := a.Verify(req)
	assertCode(t, err, CodeInvalidSignature)
}

func TestWrongSecretRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, _ := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed(id, "wrong-key", now, "nonce-1", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeInvalidSignature)
}

func TestStaleTimestampRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	// Sign with a timestamp 301s in the past.
	past := now.Add(-301 * time.Second)
	req := signed(id, key, past, "nonce-1", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeStaleTimestamp)
}

func TestFutureTimestampRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	future := now.Add(301 * time.Second)
	req := signed(id, key, future, "nonce-1", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeStaleTimestamp)
}

func TestNonceReuseRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed(id, key, now, "nonce-dup", body)
	if _, err := a.Verify(req); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	// Second identical request → nonce reuse.
	req2 := signed(id, key, now, "nonce-dup", body)
	_, err := a.Verify(req2)
	assertCode(t, err, CodeNonceReused)
}

func TestDenylistedReporterRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	if err := db.DenylistReporter(id, "abuse"); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"batch_id":"b1"}`)
	req := signed(id, key, now, "nonce-1", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeReporterDenylisted)
}

func TestUnknownReporterRejected(t *testing.T) {
	now := time.Now()
	a, _ := newAuth(t, now)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed("nope", "key", now, "nonce-1", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeUnknownReporter)
}

func TestRegisterStoresHashNotSecret(t *testing.T) {
	_, db := newAuth(t, time.Now())
	resp, err := Register(db, RegisterRequest{
		SchemaVersion: 1, InstallID: "i", Capabilities: []string{"behavior_summary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := db.GetReporter(resp.ReporterID)
	if r.SecretHash == resp.ReporterSecret {
		t.Fatal("stored secret_hash must not equal the raw secret")
	}
	if r.SecretHash != HashSecret(resp.ReporterSecret) {
		t.Fatal("stored hash must be SHA-256 of the secret")
	}
	if resp.Config.MinUploadIntervalSeconds != 900 || resp.Config.MaxBatchItems != 250 {
		t.Fatalf("unexpected config: %+v", resp.Config)
	}
}

func TestValidateRegisterRejectsUnknownCapability(t *testing.T) {
	err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: "i",
		Capabilities: []string{"not_a_kind"}})
	if err == nil {
		t.Fatal("expected unknown capability rejection")
	}
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T (%v)", err, err)
	}
	if ae.Code != want {
		t.Fatalf("expected code %s, got %s", want, ae.Code)
	}
}
