package auth

import (
	"context"
	"net/http"
	"strings"
)

// ContextKeys for storing auth data in request context
type ContextKey string

const (
	ContextKeyToken ContextKey = "auth_token"
	ContextKeyScope ContextKey = "auth_scope"
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
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			// Extract Bearer token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing Authorization header", http.StatusUnauthorized)
				return
			}

			// Parse "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
				return
			}

			rawToken := parts[1]

			// Validate the token
			token, err := tv.ValidateToken(rawToken)
			if err != nil {
				http.Error(w, "invalid or revoked token", http.StatusUnauthorized)
				return
			}

			// Add token info to context
			ctx := context.WithValue(r.Context(), ContextKeyToken, token)
			ctx = context.WithValue(ctx, ContextKeyScope, token.Scope)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
