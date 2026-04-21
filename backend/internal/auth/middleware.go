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

			// Admin scope can access anything
			if scope == ScopeAdmin {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the actual scope matches required
			if scope != requiredScope {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
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
