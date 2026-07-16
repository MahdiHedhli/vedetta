package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/store"
)

func TestEnrollmentStore(t *testing.T) {
	s := NewEnrollmentStore()

	// A generic new-sensor code: single-use, enrolls any new sensor_id.
	code, _ := s.Generate()
	if code == "" {
		t.Fatal("expected a non-empty code")
	}
	if !s.ConsumeNewSensor(code, "sensor-x") {
		t.Fatal("a freshly generated code should consume once for a new sensor")
	}
	if s.ConsumeNewSensor(code, "sensor-x") {
		t.Fatal("a code must be single-use")
	}
	if s.ConsumeNewSensor("NOPE-NOPE-NOPE-NOPE", "sensor-x") {
		t.Fatal("an unknown code must not consume")
	}
	if s.ConsumeNewSensor("", "sensor-x") {
		t.Fatal("an empty code must not consume")
	}
	if s.ConsumeNewSensor("some-code", "") {
		t.Fatal("an empty sensor_id must not consume")
	}

	// A generic code must NOT be usable to RESET an existing sensor, and refusing it
	// must NOT spend it — it stays valid for its intended new-sensor enrollment.
	generic, _ := s.Generate()
	if s.ConsumeReset(generic, "sensor-y") {
		t.Fatal("a generic new-sensor code must not reset an existing sensor")
	}
	if !s.ConsumeNewSensor(generic, "sensor-y") {
		t.Fatal("a generic code refused for reset must remain valid for new-sensor enrollment")
	}

	// A bound reset code resets ONLY its sensor; a wrong sensor_id is refused
	// without spending it, and the code cannot enroll a different new sensor.
	bound, _ := s.GenerateForSensor("sensor-z")
	if s.ConsumeReset(bound, "sensor-wrong") {
		t.Fatal("a reset code bound to sensor-z must not reset a different sensor")
	}
	if s.ConsumeNewSensor(bound, "sensor-other") {
		t.Fatal("a reset code bound to sensor-z must not enroll a different new sensor")
	}
	if !s.ConsumeReset(bound, "sensor-z") {
		t.Fatal("a reset code bound to sensor-z must reset sensor-z")
	}
	if s.ConsumeReset(bound, "sensor-z") {
		t.Fatal("a bound reset code must be single-use")
	}
}

// TestSensorEnrollmentRequiredAfterAdmin is the beta-gate B1a regression: once an
// admin exists, a brand-new sensor cannot register without an admin bearer or a
// valid single-use enrollment code.
func TestSensorEnrollmentRequiredAfterAdmin(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	admin := createTestToken(t, db, auth.ScopeAdmin, "") // an admin now exists

	body := func(id string) []byte {
		return []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
	}
	ipN := 0
	register := func(id, bearer, code string) *httptest.ResponseRecorder {
		ipN++
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body(id)))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", 10+ipN) // distinct IP: dodge the 5/min limiter
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// 1. New sensor, no admin bearer, no code, but an admin exists -> rejected.
	if w := register("sensor-a", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 registering a new sensor without a code once an admin exists, got %d: %s", w.Code, w.Body.String())
	}

	// 2. An admin bearer may enroll a new sensor with no code.
	if w := register("sensor-b", admin, ""); w.Code != http.StatusOK {
		t.Fatalf("expected 200 enrolling with an admin bearer, got %d: %s", w.Code, w.Body.String())
	}

	// 3. A minted enrollment code works once, then is single-use.
	code := mintEnrollmentCode(t, router, admin)
	if w := register("sensor-c", "", code); w.Code != http.StatusOK {
		t.Fatalf("expected 200 enrolling with a valid code, got %d: %s", w.Code, w.Body.String())
	}
	if w := register("sensor-d", "", code); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 reusing a consumed code, got %d: %s", w.Code, w.Body.String())
	}
}

// TestEnrollmentIdempotentReplay is the Issue #44 regression: Core consumes the
// single-use code and mints the sensor's only raw bearer before the HTTP response
// reaches the sensor. If that first response is lost, a retry with the SAME code
// must return the SAME raw token (200), not a 401 — otherwise the first sensor is
// permanently stranded. A DIFFERENT caller replaying the code must still be denied.
func TestEnrollmentIdempotentReplay(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)

	admin := createTestToken(t, db, auth.ScopeAdmin, "") // an admin now exists

	ipN := 0
	register := func(id, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", 10+ipN) // distinct IP: dodge the 5/min limiter
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	registrationOf := func(w *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		var m map[string]any
		if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
			t.Fatalf("decode register response: %v", err)
		}
		tok, _ := m["auth_token"].(string)
		epoch, _ := m["delivery_epoch"].(string)
		return tok, epoch
	}

	code := mintEnrollmentCode(t, router, admin)

	// First registration succeeds and mints the sensor's only raw token.
	w1 := register("sensor-idem", code)
	if w1.Code != http.StatusOK {
		t.Fatalf("first register: expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	tok1, epoch1 := registrationOf(w1)
	if tok1 == "" {
		t.Fatal("first register did not return an auth_token")
	}
	if epoch1 == "" {
		t.Fatal("first register did not return a delivery epoch")
	}

	// Simulate a delivery-session subsystem failure after provisioning has
	// committed. The raw bearer must still be replayed; returning 500 here would
	// strand the sensor because the identity and token already exist.
	if _, err := db.Exec(`DROP TABLE arp_cache_delivery_epochs`); err != nil {
		t.Fatalf("disable delivery epoch store: %v", err)
	}

	// The sensor "lost" that response. It retries with the SAME code and SAME
	// sensor_id — it must recover the SAME token, not a 401.
	w2 := register("sensor-idem", code)
	if w2.Code != http.StatusOK {
		t.Fatalf("idempotent retry: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	tok2, epoch2 := registrationOf(w2)
	if tok2 != tok1 {
		t.Fatalf("idempotent retry returned a different token: %q vs %q", tok2, tok1)
	}
	if epoch2 != "" {
		t.Fatalf("failed delivery-session issue returned epoch %q, want provisional empty value", epoch2)
	}

	// The recovered token must actually authenticate.
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok2); err != nil {
		t.Fatalf("recovered token does not validate: %v", err)
	}

	// Single-use against a DIFFERENT caller is preserved: another sensor_id
	// replaying the same consumed code gets nothing.
	if w := register("sensor-other", code); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a different sensor replaying a consumed code, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSensorReset_ViaFreshEnrollmentCode is the Issue #44 RECOVERY regression: a
// sensor stranded (--reset, a lost response past the idempotency window, a Core
// restart, or local token corruption) has no local token while the server-side
// token still exists. It must be able to re-enroll by presenting a FRESH
// admin-minted single-use enrollment code — Core revokes the stale token and
// issues a new one, so recovery needs no hidden admin reset API. A bogus code
// must NOT reset it or revoke the real token.
func TestSensorReset_ViaFreshEnrollmentCode(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	ipN := 0
	register := func(id, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", 10+ipN) // distinct IP: dodge the limiter
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	tokenOf := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var m map[string]any
		_ = json.NewDecoder(w.Body).Decode(&m)
		tok, _ := m["auth_token"].(string)
		return tok
	}

	// Enroll the sensor for the first time.
	tok1 := tokenOf(register("sensor-reset", mintEnrollmentCode(t, router, admin)))
	if tok1 == "" {
		t.Fatal("first enroll returned no token")
	}

	// Stranded: no local token, but the server token still exists. Re-register with
	// nothing -> 401 (not silently reset); a BOGUS code -> 401 and the real token
	// must survive (no revoke-before-validate DoS).
	if w := register("sensor-reset", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("stranded re-register with nothing: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if w := register("sensor-reset", "WRONG-WRONG-WRONG-WRONG"); w.Code != http.StatusUnauthorized {
		t.Fatalf("stranded re-register with a bogus code: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok1); err != nil {
		t.Fatalf("original token must survive a failed reset attempt: %v", err)
	}

	// A GENERIC new-sensor code must NOT reset an existing sensor (beta-gate B1a):
	// possession of any enrollment code cannot take over a guessable sensor_id.
	if w := register("sensor-reset", mintEnrollmentCode(t, router, admin)); w.Code != http.StatusUnauthorized {
		t.Fatalf("generic code must not reset an existing sensor: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok1); err != nil {
		t.Fatalf("original token must survive a generic-code reset attempt: %v", err)
	}

	// A RESET code BOUND to this sensor_id recovers it: revoke the stale token, issue a NEW one.
	w2 := register("sensor-reset", mintResetCode(t, router, admin, "sensor-reset"))
	if w2.Code != http.StatusOK {
		t.Fatalf("reset via bound code: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	tok2 := tokenOf(w2)
	if tok2 == "" || tok2 == tok1 {
		t.Fatalf("reset must issue a NEW token: tok1=%q tok2=%q", tok1, tok2)
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok2); err != nil {
		t.Fatalf("new token must validate: %v", err)
	}
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tok1); err == nil {
		t.Fatal("the stale token must be revoked after a successful reset")
	}
}

func mintEnrollmentCode(t *testing.T, router http.Handler, adminBearer string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/enrollment-codes", nil)
	req.Header.Set("Authorization", "Bearer "+adminBearer)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint enrollment code: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.NewDecoder(w.Body).Decode(&m)
	code, _ := m["enrollment_code"].(string)
	if code == "" {
		t.Fatal("expected an enrollment_code in the response")
	}
	return code
}

// mintResetCode mints a RESET code bound to an existing sensor_id (POST
// /enrollment-codes with a {"sensor_id":...} body).
func mintResetCode(t *testing.T, router http.Handler, adminBearer, sensorID string) string {
	t.Helper()
	body := []byte(fmt.Sprintf(`{"sensor_id":%q}`, sensorID))
	req := httptest.NewRequest("POST", "/api/v1/enrollment-codes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminBearer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint reset code: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.NewDecoder(w.Body).Decode(&m)
	code, _ := m["enrollment_code"].(string)
	if code == "" {
		t.Fatal("expected an enrollment_code in the reset response")
	}
	return code
}

// TestSensorIDCollisionDoesNotTakeover is the beta-gate B1a regression for the
// "two fresh Pis named raspberrypi" case: a second device that collides on
// sensor_id (hostname-os-arch) must NOT be able to displace the first with a
// generic enrollment code. The collision surfaces as a 401, and the first
// sensor's token keeps working.
func TestSensorIDCollisionDoesNotTakeover(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	ipN := 0
	register := func(id, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"raspberrypi","os":"linux","arch":"arm64","cidr":"192.168.1.0/24","version":"t"}`, id))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", 40+ipN)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	tokenOf := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		var m map[string]any
		_ = json.NewDecoder(w.Body).Decode(&m)
		tok, _ := m["auth_token"].(string)
		return tok
	}

	// Pi A enrolls first with its own code.
	tokA := tokenOf(register("raspberrypi-linux-arm64", mintEnrollmentCode(t, router, admin)))
	if tokA == "" {
		t.Fatal("first Pi got no token")
	}

	// Pi B (same hostname/os/arch → same sensor_id) presents its OWN fresh, valid
	// generic code. It must be refused (collision surfaced), not silently take over.
	if w := register("raspberrypi-linux-arm64", mintEnrollmentCode(t, router, admin)); w.Code != http.StatusUnauthorized {
		t.Fatalf("colliding second Pi with a generic code: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// Pi A's token still works.
	if _, err := auth.ValidateAuthorizationHeader(db, "Bearer "+tokA); err != nil {
		t.Fatalf("first Pi token must survive a colliding enrollment: %v", err)
	}
	// Exactly one active sensor token exists for the id.
	if n := activeSensorTokenCount(t, db, "raspberrypi-linux-arm64"); n != 1 {
		t.Fatalf("expected exactly 1 active sensor token after a blocked takeover, got %d", n)
	}
}

// TestConcurrentResetLeavesOneActiveToken is the beta-gate B1a concurrency
// regression: firing many bound reset codes at one sensor simultaneously must
// leave exactly ONE active token — never several valid credentials at once.
func TestConcurrentResetLeavesOneActiveToken(t *testing.T) {
	// A file-backed DB (not the shared :memory: helper): concurrent registrations
	// open multiple pooled connections, and a lone :memory: DSN gives each its own
	// empty schema. Production always uses a WAL file DB, which this mirrors.
	db, err := store.Open(filepath.Join(t.TempDir(), "vedetta-conc-test.db"))
	if err != nil {
		t.Fatalf("open file-backed test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	srv := &Server{DB: db, SetupCode: testSetupCode}
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	// Enroll the sensor once.
	{
		body := []byte(`{"sensor_id":"sensor-conc","hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`)
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Vedetta-Enrollment-Code", mintEnrollmentCode(t, router, admin))
		req.RemoteAddr = "203.0.113.5:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("initial enroll: expected 200, got %d: %s", w.Code, w.Body.String())
		}
	}

	// Pre-mint N bound reset codes, then fire them concurrently.
	const n = 20
	codes := make([]string, n)
	for i := range codes {
		codes[i] = mintResetCode(t, router, admin, "sensor-conc")
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(code string, ip int) {
			defer wg.Done()
			body := []byte(`{"sensor_id":"sensor-conc","hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`)
			req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
			req.RemoteAddr = fmt.Sprintf("10.10.%d.%d:1234", ip/250, ip%250)
			router.ServeHTTP(httptest.NewRecorder(), req)
		}(codes[i], i)
	}
	wg.Wait()

	if got := activeSensorTokenCount(t, db, "sensor-conc"); got != 1 {
		t.Fatalf("after %d concurrent resets, expected exactly 1 active sensor token, got %d", n, got)
	}
}

// activeSensorTokenCount counts non-revoked sensor-scoped tokens for a sensor_id.
func activeSensorTokenCount(t *testing.T, db *store.DB, sensorID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM api_tokens WHERE sensor_id = ? AND scope = 'sensor' AND revoked = 0`,
		sensorID,
	).Scan(&count); err != nil {
		t.Fatalf("count active sensor tokens: %v", err)
	}
	return count
}

// TestReplayAfterResetDoesNotReturnDeadToken guards the idempotent-replay path:
// if a sensor is reset after its enrollment code was first redeemed, replaying
// the ORIGINAL code must NOT return the now-revoked token with a misleading 200.
// The sensor should be told to present a fresh reset code (401) rather than
// believing it re-enrolled while holding a dead credential.
func TestReplayAfterResetDoesNotReturnDeadToken(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	ipN := 0
	register := func(id, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":"h","os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", 70+ipN)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	tokenOf := func(w *httptest.ResponseRecorder) string {
		var m map[string]any
		_ = json.NewDecoder(w.Body).Decode(&m)
		tok, _ := m["auth_token"].(string)
		return tok
	}

	// Enroll with a generic code (which we keep, to replay later).
	code := mintEnrollmentCode(t, router, admin)
	tok1 := tokenOf(register("sensor-replay", code))
	if tok1 == "" {
		t.Fatal("enroll returned no token")
	}

	// Reset the sensor with a bound reset code → tok1 is revoked, tok2 issued.
	if w := register("sensor-replay", mintResetCode(t, router, admin, "sensor-replay")); w.Code != http.StatusOK {
		t.Fatalf("reset: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The sensor, unaware of the reset, replays its ORIGINAL enroll code. It must not
	// receive the revoked tok1 — expect a 401 pointing it at a fresh reset code.
	w3 := register("sensor-replay", code)
	if w3.Code == http.StatusOK && tokenOf(w3) == tok1 {
		t.Fatal("replay after reset handed back the revoked original token")
	}
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("replay of original code after reset: expected 401, got %d: %s", w3.Code, w3.Body.String())
	}
}

// TestRevokedSensorCannotBeReEnrolledWithGenericCode is the beta-gate B1a
// regression Sol found: after an admin REVOKES a sensor, its row still exists but
// has no active token. Keying new-vs-reset on active-token existence let a generic
// new-sensor code re-enroll it, silently undoing the revocation and overwriting
// metadata. It must now be rejected; only an admin-minted bound reset code may
// reactivate it.
func TestRevokedSensorCannotBeReEnrolledWithGenericCode(t *testing.T) {
	srv, db := setupTestServer(t)
	router := NewRouter(srv)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")

	ipN := 0
	register := func(id, hostname, code string) *httptest.ResponseRecorder {
		ipN++
		body := []byte(fmt.Sprintf(`{"sensor_id":%q,"hostname":%q,"os":"linux","arch":"amd64","cidr":"192.168.1.0/24","version":"t"}`, id, hostname))
		req := httptest.NewRequest("POST", "/api/v1/sensor/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if code != "" {
			req.Header.Set("X-Vedetta-Enrollment-Code", code)
		}
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1234", 30+ipN)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	hostnameOf := func() string {
		var h string
		_ = db.QueryRow(`SELECT hostname FROM sensors WHERE sensor_id = ?`, "revoked-target").Scan(&h)
		return h
	}

	// 1. Enroll the target.
	if w := register("revoked-target", "orig-host", mintEnrollmentCode(t, router, admin)); w.Code != http.StatusOK {
		t.Fatalf("initial enroll: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Admin revokes the target's sensor token. Row remains; no active token.
	if err := db.DeleteTokensBySensor("revoked-target"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n := activeSensorTokenCount(t, db, "revoked-target"); n != 0 {
		t.Fatalf("after revoke want 0 active tokens, got %d", n)
	}

	// 3. A generic new-sensor code must NOT re-enroll the revoked id, and must not
	//    overwrite its metadata.
	if w := register("revoked-target", "attacker-host", mintEnrollmentCode(t, router, admin)); w.Code != http.StatusUnauthorized {
		t.Fatalf("generic re-enroll of a revoked sensor: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	if got := hostnameOf(); got != "orig-host" {
		t.Fatalf("revoked sensor metadata was overwritten via a generic code: hostname=%q", got)
	}
	if n := activeSensorTokenCount(t, db, "revoked-target"); n != 0 {
		t.Fatalf("a token was minted for a revoked sensor via a generic code: %d active", n)
	}

	// 4. An admin-minted bound reset/reactivation code succeeds.
	if w := register("revoked-target", "orig-host", mintResetCode(t, router, admin, "revoked-target")); w.Code != http.StatusOK {
		t.Fatalf("bound reset of a revoked sensor: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if n := activeSensorTokenCount(t, db, "revoked-target"); n != 1 {
		t.Fatalf("after bound reset want exactly 1 active token, got %d", n)
	}
}
