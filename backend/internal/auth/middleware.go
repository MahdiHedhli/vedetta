package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ContextKeys for storing auth data in request context
type ContextKey string

const (
	ContextKeyToken ContextKey = "auth_token"
	ContextKeyScope ContextKey = "auth_scope"
)

var (
	ErrMissingAuthorizationHeader = errors.New("missing Authorization header")
	ErrInvalidAuthorizationHeader = errors.New("invalid Authorization header format")
	ErrInvalidBearerToken         = errors.New("invalid or revoked token")
)

// TokenValidator is the interface the auth middleware needs from the storage layer.
// This avoids a circular import between auth and store.
type TokenValidator interface {
	CountTokens() (int, error)
	// HasActiveAdminToken reports whether a non-revoked admin token exists. Admin
	// bootstrap gates on this (not on CountTokens), so an auto-issued sensor token
	// cannot close the first-admin window (beta-gate B1b).
	HasActiveAdminToken() (bool, error)
	ValidateToken(rawToken string) (*Token, error)
}

// RequireAuth returns middleware that validates Bearer tokens from Authorization headers.
// If no tokens exist in the database yet (fresh install), all requests bypass auth
// to allow initial setup and sensor registration.
func RequireAuth(tv TokenValidator) func(next http.Handler) http.Handler {
	return requireAuth(tv, true)
}

// RequireStrictAuth always requires a valid Bearer token, even during bootstrap.
// Use this on machine-to-machine endpoints that must never accept unauthenticated traffic.
func RequireStrictAuth(tv TokenValidator) func(next http.Handler) http.Handler {
	return requireAuth(tv, false)
}

// RequireAdmin returns middleware suitable for dashboard / human admin routes.
// - If no tokens exist yet (fresh install / bootstrap), all requests pass through.
// - Once any token exists, a valid Bearer token with ScopeAdmin is required.
// This is the recommended middleware for all UI-facing management endpoints.
func RequireAdmin(tv TokenValidator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hasAdmin, err := tv.HasActiveAdminToken()
			if err != nil {
				http.Error(w, "auth: failed to check token store", http.StatusInternalServerError)
				return
			}

			if !hasAdmin {
				// Bootstrap mode: no active admin exists yet, so allow initial setup
				// (including creation of the first admin token). Gating on active-admin
				// rather than total token count means an auto-issued sensor/ingest token
				// can no longer lock the operator out of admin enrollment (beta-gate B1b).
				next.ServeHTTP(w, r)
				return
			}

			// Auth is configured — require a valid admin token
			token, err := ValidateAuthorizationHeader(tv, r.Header.Get("Authorization"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if token.Scope != ScopeAdmin {
				http.Error(w, "admin scope required", http.StatusForbidden)
				return
			}

			// Populate context for handlers that want it
			ctx := context.WithValue(r.Context(), ContextKeyToken, token)
			ctx = context.WithValue(ctx, ContextKeyScope, token.Scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireStrictAdmin always requires a valid admin-scoped Bearer token, even
// during bootstrap (NO active-admin bypass). Use it for every admin route EXCEPT
// first-admin creation: those routes must be unavailable until an admin exists,
// so a LAN peer cannot mint enrollment codes, plant scan targets, or mutate
// settings before setup completes (GHSA-6cmx). First-admin creation keeps
// RequireAdmin (which self-gates on the single-use setup code in the handler).
func RequireStrictAdmin(tv TokenValidator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := ValidateAuthorizationHeader(tv, r.Header.Get("Authorization"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if token.Scope != ScopeAdmin {
				http.Error(w, "admin scope required", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), ContextKeyToken, token)
			ctx = context.WithValue(ctx, ContextKeyScope, token.Scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRead returns middleware for read-only dashboard / query routes
// (GET events, devices, status, and similar). It mirrors RequireAdmin's
// bootstrap semantics so first-run setup is never locked out:
//   - If no active admin token exists yet (fresh install / bootstrap), all
//     requests pass through so the operator can complete initial setup.
//   - Once an active admin exists, a valid Bearer token is required and its
//     scope must satisfy ScopeRead (admin implies read; a read token qualifies;
//     sensor/ingest machine tokens do not). Unauthenticated reads are rejected.
//
// This is the recommended middleware for all read-only, human-facing endpoints
// that were previously public (beta-gate B6).
func RequireRead(tv TokenValidator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hasAdmin, err := tv.HasActiveAdminToken()
			if err != nil {
				http.Error(w, "auth: failed to check token store", http.StatusInternalServerError)
				return
			}

			if !hasAdmin {
				// Bootstrap mode: no active admin yet — keep reads open so the
				// onboarding wizard and first-run setup work before any token
				// is minted. Keying on active-admin (not total token count)
				// matches RequireAdmin, so an auto-issued sensor/ingest token
				// does not prematurely close the open-read window (beta-gate B1b).
				next.ServeHTTP(w, r)
				return
			}

			token, err := ValidateAuthorizationHeader(tv, r.Header.Get("Authorization"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if !ScopeSatisfies(token.Scope, ScopeRead) {
				http.Error(w, "read scope required", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyToken, token)
			ctx = context.WithValue(ctx, ContextKeyScope, token.Scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requireAuth(tv TokenValidator, allowBootstrapBypass bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowBootstrapBypass {
				// Check if any tokens exist in the database
				tokenCount, err := tv.CountTokens()
				if err != nil {
					// Error checking tokens — deny for safety
					http.Error(w, "auth: failed to check token store", http.StatusInternalServerError)
					return
				}

				// Fresh install mode: no tokens exist yet, bypass auth for setup
				if tokenCount == 0 {
					next.ServeHTTP(w, r)
					return
				}
			}

			token, err := ValidateAuthorizationHeader(tv, r.Header.Get("Authorization"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			// Add token info to context
			ctx := context.WithValue(r.Context(), ContextKeyToken, token)
			ctx = context.WithValue(ctx, ContextKeyScope, token.Scope)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateAuthorizationHeader parses and validates a Bearer token.
func ValidateAuthorizationHeader(tv TokenValidator, authHeader string) (*Token, error) {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return nil, ErrMissingAuthorizationHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || strings.TrimSpace(parts[1]) == "" {
		return nil, ErrInvalidAuthorizationHeader
	}

	token, err := tv.ValidateToken(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, ErrInvalidBearerToken
	}

	return token, nil
}

// RequireScope returns middleware that checks the authenticated token has the required scope.
// Must be used after RequireAuth.
func RequireScope(requiredScope TokenScope) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope, ok := r.Context().Value(ContextKeyScope).(TokenScope)
			if !ok {
				http.Error(w, "not authenticated", http.StatusUnauthorized)
				return
			}

			// Scope hierarchy (admin implies everything; otherwise exact match)
			// lives in ScopeSatisfies so read/admin gating stays consistent.
			if !ScopeSatisfies(scope, requiredScope) {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireScopeOrBootstrap applies a scope gate after RequireAuth while retaining
// RequireAuth's zero-token bootstrap bypass. A missing scope means RequireAuth
// deliberately admitted a fresh installation; once a token was authenticated,
// the normal hierarchy applies (admin may satisfy machine scopes).
func RequireScopeOrBootstrap(requiredScope TokenScope) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope, ok := r.Context().Value(ContextKeyScope).(TokenScope)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if !ScopeSatisfies(scope, requiredScope) {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DenyReadScope rejects read-scoped tokens on state-mutating machine endpoints
// (e.g. POST /ingest) that are otherwise guarded by RequireAuth. A ScopeRead
// token is a least-privilege *viewer* credential and must never be able to write
// (beta-gate B6). This is a deny-list guard layered AFTER RequireAuth: it is a
// no-op during bootstrap (no scope in context) and for every non-read scope, so
// it removes read-token write access without tightening any existing path —
// admin/ingest/sensor tokens and the first-run bootstrap window are unaffected.
func DenyReadScope() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope, ok := r.Context().Value(ContextKeyScope).(TokenScope); ok && scope == ScopeRead {
				http.Error(w, "read-only token cannot write", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireExactScope returns middleware that checks the authenticated token matches the required scope exactly.
// Use this for least-privilege machine credentials where admin tokens should not be accepted as a substitute.
func RequireExactScope(requiredScope TokenScope) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope, ok := r.Context().Value(ContextKeyScope).(TokenScope)
			if !ok {
				http.Error(w, "not authenticated", http.StatusUnauthorized)
				return
			}
			if scope != requiredScope {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetTokenFromContext extracts the authenticated token from request context.
func GetTokenFromContext(r *http.Request) *Token {
	token, ok := r.Context().Value(ContextKeyToken).(*Token)
	if !ok {
		return nil
	}
	return token
}

// GetScopeFromContext extracts the token scope from request context.
func GetScopeFromContext(r *http.Request) TokenScope {
	scope, ok := r.Context().Value(ContextKeyScope).(TokenScope)
	if !ok {
		return ""
	}
	return scope
}
