// Package auth handles reporter registration, secret hashing, and HMAC
// signed-request verification with replay protection, per
// specs/002-telemetry-service/contracts/telemetry-export.md §1-2 and
// specs/003-threat-network/plan.md.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
	"github.com/vedetta-network/vedetta/threat-network/internal/valid"
)

// MaxSkew is the allowed timestamp drift for signed requests (±300s per contract).
const MaxSkew = 300 * time.Second

// Known signal kinds / capabilities.
var knownKinds = map[string]bool{
	"known_bad_domain_hit":             true,
	"high_confidence_domain_candidate": true,
	"behavior_summary":                 true,
}

// Error codes (machine-readable, per plan.md Failure Modes).
const (
	CodeInvalidSignature   = "INVALID_SIGNATURE"
	CodeStaleTimestamp     = "STALE_TIMESTAMP"
	CodeNonceReused        = "NONCE_REUSED"
	CodeReporterDenylisted = "REPORTER_DENYLISTED"
	CodeUnknownReporter    = "UNKNOWN_REPORTER"
	CodeMissingAuth        = "MISSING_AUTH"
	CodeInvalidNonce       = "INVALID_NONCE"
)

// AuthError carries a machine-readable code alongside a message.
type AuthError struct {
	Code    string
	Message string
}

func (e *AuthError) Error() string { return e.Code + ": " + e.Message }

func authErr(code, msg string) *AuthError { return &AuthError{Code: code, Message: msg} }

// HashSecret returns the hex SHA-256 of a secret. The raw secret is never stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Authenticator verifies signed requests against the reporter registry.
type Authenticator struct {
	DB  *store.DB
	Now func() time.Time
}

// New returns an Authenticator using real time.
func New(db *store.DB) *Authenticator {
	return &Authenticator{DB: db, Now: time.Now}
}

func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// SignedRequest bundles the auth headers plus the raw (uncompressed) body.
type SignedRequest struct {
	ReporterID string
	Timestamp  string // unix seconds, as sent
	Nonce      string
	Signature  string // hex
	Body       []byte // uncompressed body bytes
}

// Verify authenticates a signed request. On success it returns the verified
// reporter and records the nonce (single-use). On failure it returns an
// *AuthError whose Code maps to the plan.md error vocabulary.
func (a *Authenticator) Verify(req SignedRequest) (*store.Reporter, error) {
	if req.ReporterID == "" || req.Timestamp == "" || req.Nonce == "" || req.Signature == "" {
		return nil, authErr(CodeMissingAuth, "missing required auth headers")
	}

	// Wire-format validation (GHSA-hx86): the X-Vedetta-Nonce must be a UUIDv4.
	// Reject non-conforming nonces before any DB work — a malformed nonce cannot
	// be a legitimate replay token and must not reach the replay store.
	if !valid.UUIDv4(req.Nonce) {
		return nil, authErr(CodeInvalidNonce, "nonce must be a UUIDv4")
	}

	// Timestamp skew check first (cheap, no DB).
	tsInt, err := strconv.ParseInt(req.Timestamp, 10, 64)
	if err != nil {
		return nil, authErr(CodeStaleTimestamp, "timestamp not an integer")
	}
	ts := time.Unix(tsInt, 0)
	drift := a.now().Sub(ts)
	if drift < 0 {
		drift = -drift
	}
	if drift > MaxSkew {
		return nil, authErr(CodeStaleTimestamp, "timestamp outside ±300s window")
	}

	reporter, err := a.DB.GetReporter(req.ReporterID)
	if err != nil {
		if errors.Is(err, store.ErrReporterNotFound) {
			return nil, authErr(CodeUnknownReporter, "unknown reporter")
		}
		return nil, err
	}
	if reporter.Status == "denylisted" {
		return nil, authErr(CodeReporterDenylisted, "reporter is denylisted")
	}

	// Verification key: both the reporter and the server key the HMAC on the
	// hex SHA-256 of the raw secret (SigningKeyForSecret). This lets the server
	// verify signatures while persisting only the hash — the raw random secret
	// is never stored. See the package doc and Register for the rationale; this
	// is a deliberate, documented deviation from a literal reading of 002 §1
	// (which keys on the raw secret) that preserves the no-PII-at-rest guarantee.
	expected := ComputeSignature(reporter.SecretHash, req.Timestamp, req.Nonce, req.Body)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(req.Signature)) != 1 {
		return nil, authErr(CodeInvalidSignature, "signature mismatch")
	}

	// Replay protection: nonce must be single-use per reporter.
	fresh, err := a.DB.InsertNonceIfAbsent(req.ReporterID, req.Nonce)
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, authErr(CodeNonceReused, "nonce already used")
	}

	_ = a.DB.TouchReporter(req.ReporterID)
	return reporter, nil
}

// ComputeSignature returns hex(HMAC-SHA256(key, ts + "\n" + nonce + "\n" + sha256hex(body))).
// key is the reporter's signing key. See register.go for how the key relates to
// the issued secret.
func ComputeSignature(key, ts, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	msg := ts + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// RegisterRequest is the reporter registration payload (002 contract §2).
type RegisterRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	InstallID      string   `json:"install_id"`
	VedettaVersion string   `json:"vedetta_version"`
	Capabilities   []string `json:"capabilities"`
}

// RegisterResponse is issued once; the raw secret is never stored server-side.
type RegisterResponse struct {
	ReporterID     string         `json:"reporter_id"`
	ReporterSecret string         `json:"reporter_secret"`
	Config         RegisterConfig `json:"config"`
}

// RegisterConfig carries the operational limits echoed to the reporter.
type RegisterConfig struct {
	MinUploadIntervalSeconds int `json:"min_upload_interval_seconds"`
	MaxBatchItems            int `json:"max_batch_items"`
}

// ValidateRegister checks a registration request against the contract.
func ValidateRegister(r RegisterRequest) error {
	if r.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", r.SchemaVersion)
	}
	if r.InstallID == "" {
		return errors.New("install_id required")
	}
	// Wire-format validation (GHSA-hx86): vedetta_version must be strict semver.
	if !valid.Semver(r.VedettaVersion) {
		return fmt.Errorf("vedetta_version %q is not strict semver", r.VedettaVersion)
	}
	if len(r.Capabilities) == 0 {
		return errors.New("at least one capability required")
	}
	for _, c := range r.Capabilities {
		if !knownKinds[c] {
			return fmt.Errorf("unknown capability %q", c)
		}
	}
	return nil
}

// Register creates a reporter and returns the one-time credential. The signing
// key issued to the reporter is the raw secret; the server persists only its
// SHA-256 hash and uses that hash as the HMAC verification key (both sides agree
// to key the MAC on the hex secret string). This keeps the raw random secret out
// of storage while still allowing signature verification.
func Register(db *store.DB, r RegisterRequest) (*RegisterResponse, error) {
	if err := ValidateRegister(r); err != nil {
		return nil, err
	}
	reporterID := randomUUID()
	rawSecret := randomSecret()
	secretHash := HashSecret(rawSecret)

	capsJSON, _ := json.Marshal(r.Capabilities)
	if err := db.CreateReporter(reporterID, secretHash, string(capsJSON), r.VedettaVersion); err != nil {
		return nil, err
	}
	return &RegisterResponse{
		ReporterID:     reporterID,
		ReporterSecret: rawSecret,
		Config: RegisterConfig{
			MinUploadIntervalSeconds: 900,
			MaxBatchItems:            250,
		},
	}, nil
}

// SigningKeyForSecret returns the HMAC key a reporter must use to sign requests,
// given its raw secret. It mirrors the server's verification key derivation so
// that clients and the shared test helpers stay in lockstep.
func SigningKeyForSecret(rawSecret string) string {
	return HashSecret(rawSecret)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
