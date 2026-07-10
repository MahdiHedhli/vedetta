package auth

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
	"github.com/vedetta-network/vedetta/threat-network/internal/valid"
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
	req := signed(id, key, now, "11111111-1111-4111-8111-111111111111", body)
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
	req := signed(id, key, now, "11111111-1111-4111-8111-111111111111", []byte(`{"batch_id":"b1"}`))
	req.Body = []byte(`{"batch_id":"TAMPERED"}`) // signature no longer matches
	_, err := a.Verify(req)
	assertCode(t, err, CodeInvalidSignature)
}

func TestWrongSecretRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, _ := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed(id, "wrong-key", now, "11111111-1111-4111-8111-111111111111", body)
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
	req := signed(id, key, past, "11111111-1111-4111-8111-111111111111", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeStaleTimestamp)
}

func TestFutureTimestampRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	future := now.Add(301 * time.Second)
	req := signed(id, key, future, "11111111-1111-4111-8111-111111111111", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeStaleTimestamp)
}

func TestNonceReuseRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed(id, key, now, "22222222-2222-4222-8222-222222222222", body)
	if _, err := a.Verify(req); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	// Second identical request → nonce reuse.
	req2 := signed(id, key, now, "22222222-2222-4222-8222-222222222222", body)
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
	req := signed(id, key, now, "11111111-1111-4111-8111-111111111111", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeReporterDenylisted)
}

func TestUnknownReporterRejected(t *testing.T) {
	now := time.Now()
	a, _ := newAuth(t, now)
	body := []byte(`{"batch_id":"b1"}`)
	req := signed("nope", "key", now, "11111111-1111-4111-8111-111111111111", body)
	_, err := a.Verify(req)
	assertCode(t, err, CodeUnknownReporter)
}

func TestRegisterStoresHashNotSecret(t *testing.T) {
	_, db := newAuth(t, time.Now())
	resp, err := Register(db, RegisterRequest{
		SchemaVersion: 1, InstallID: "i", VedettaVersion: "0.1.0",
		Capabilities: []string{"behavior_summary"},
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
		VedettaVersion: "0.1.0", Capabilities: []string{"not_a_kind"}})
	if err == nil {
		t.Fatal("expected unknown capability rejection")
	}
}

// TestNonUUIDNonceRejected is the GHSA-hx86 regression: the X-Vedetta-Nonce must
// be a UUIDv4. A non-conforming nonce is rejected before any DB/replay work.
func TestNonUUIDNonceRejected(t *testing.T) {
	now := time.Now()
	a, db := newAuth(t, now)
	id, key := registerReporter(t, db)
	for _, bad := range []string{"nonce-1", "not-a-uuid", "", "11111111-1111-1111-8111-111111111111"} {
		// Sign correctly so only the nonce format is under test. Empty nonce trips
		// the missing-auth guard (also a rejection); both are acceptable failures.
		req := signed(id, key, now, bad, []byte(`{"batch_id":"b1"}`))
		if _, err := a.Verify(req); err == nil {
			t.Fatalf("non-UUID nonce %q must be rejected", bad)
		}
	}
	// A valid UUIDv4 nonce passes the format gate.
	req := signed(id, key, now, "33333333-3333-4333-8333-333333333333", []byte(`{"batch_id":"b1"}`))
	if _, err := a.Verify(req); err != nil {
		t.Fatalf("valid UUIDv4 nonce must pass, got %v", err)
	}
}

// TestValidateRegisterRejectsBadVersion is the GHSA-hx86 regression: vedetta_version
// at registration must be strict semver.
func TestValidateRegisterRejectsBadVersion(t *testing.T) {
	for _, bad := range []string{"", "v1.2.3", "1", "1.2.3.4", "latest", "1.x"} {
		err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: "i",
			VedettaVersion: bad, Capabilities: []string{"behavior_summary"}})
		if err == nil {
			t.Fatalf("non-semver vedetta_version %q must be rejected", bad)
		}
	}
	for _, ok := range []string{"0.1", "0.1.0", "1.2.3", "10.20.30", "1.2.0-dev", "0.1.0-rc.1"} {
		if err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: "i",
			VedettaVersion: ok, Capabilities: []string{"behavior_summary"}}); err != nil {
			t.Fatalf("semver vedetta_version %q must be accepted, got %v", ok, err)
		}
	}
}

// TestRegisterRejectsOverLongFields is the GHSA-7p69 over-long-field regression:
// the unbounded semver grammar accepted a ~3 MB all-digits "version" (under the
// 4 MiB body cap), which was then persisted. Every registered string field now
// has a small explicit max-length; over-long values are rejected and nothing is
// stored.
func TestRegisterRejectsOverLongFields(t *testing.T) {
	// A ~3 MB version that matches the raw semver number grammar (1.<3M digits>).
	giantVersion := "1." + strings.Repeat("9", 3<<20)

	// ValidateRegister must reject it outright.
	if err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: "i",
		VedettaVersion: giantVersion, Capabilities: []string{"behavior_summary"}}); err == nil {
		t.Fatal("a ~3 MB vedetta_version must be rejected")
	}

	// The raw format validator must also reject it (defense in depth): an over-long
	// numeric identifier must never be treated as valid semver.
	if valid.Semver(giantVersion) {
		t.Fatal("valid.Semver must reject an over-long version string")
	}

	// End-to-end: Register must fail and persist NO reporter row.
	_, db := newAuth(t, time.Now())
	if _, err := Register(db, RegisterRequest{SchemaVersion: 1, InstallID: "i",
		VedettaVersion: giantVersion, Capabilities: []string{"behavior_summary"}}); err == nil {
		t.Fatal("Register must reject a ~3 MB vedetta_version")
	}
	var reporters int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reporters`).Scan(&reporters); err != nil {
		t.Fatal(err)
	}
	if reporters != 0 {
		t.Fatalf("no reporter must be persisted for a rejected registration, got %d", reporters)
	}

	// Other over-long fields are likewise rejected.
	bigInstall := strings.Repeat("x", 1<<20)
	if err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: bigInstall,
		VedettaVersion: "1.2.3", Capabilities: []string{"behavior_summary"}}); err == nil {
		t.Fatal("an over-long install_id must be rejected")
	}
	manyCaps := make([]string, 1000)
	for i := range manyCaps {
		manyCaps[i] = "behavior_summary"
	}
	if err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: "i",
		VedettaVersion: "1.2.3", Capabilities: manyCaps}); err == nil {
		t.Fatal("an over-long capabilities list must be rejected")
	}

	// A normal registration still succeeds (no over-blocking).
	if err := ValidateRegister(RegisterRequest{SchemaVersion: 1, InstallID: "install-abc",
		VedettaVersion: "1.2.3", Capabilities: []string{"behavior_summary"}}); err != nil {
		t.Fatalf("a normal registration must still pass, got %v", err)
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
