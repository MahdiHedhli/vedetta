package store

import (
	"testing"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
)

// TestEnsureTokenFromRaw covers the collector ingest-credential provisioning
// (beta-gate B5): a token for a known raw secret is created once, is idempotent
// across restarts, and authenticates via the normal validation path.
func TestEnsureTokenFromRaw(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	const raw = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	created, err := db.EnsureTokenFromRaw(raw, auth.ScopeIngest, "compose ingest")
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if !created {
		t.Fatal("expected a token to be created on first ensure")
	}

	// Idempotent: a second call must not create a duplicate.
	created2, err := db.EnsureTokenFromRaw(raw, auth.ScopeIngest, "compose ingest")
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if created2 {
		t.Fatal("expected no new token on the second ensure (idempotent)")
	}

	// The provisioned raw token authenticates and carries the ingest scope.
	tok, err := db.ValidateToken(raw)
	if err != nil {
		t.Fatalf("validate provisioned token: %v", err)
	}
	if tok.Scope != auth.ScopeIngest {
		t.Fatalf("expected ingest scope, got %q", tok.Scope)
	}

	// Empty/whitespace secret is a no-op (no token, no error).
	if created, err := db.EnsureTokenFromRaw("   ", auth.ScopeIngest, "x"); err != nil || created {
		t.Fatalf("empty secret should be a no-op, got created=%v err=%v", created, err)
	}
}
