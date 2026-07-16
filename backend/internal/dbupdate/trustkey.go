package dbupdate

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

// trustedPublicKeyBase64 is the compiled-in ed25519 public key that signs device-DB
// bundles. It is the client's trust root: only a bundle whose manifest is signed by the
// matching private key (held solely as the VEDETTA_DB_SIGNING_KEY CI secret) is ever
// applied.
//
// PLACEHOLDER — this is intentionally empty. Generate the production keypair with
// scripts/gen-db-signing-key.sh, store the private key as the CI secret, and replace this
// constant with the printed public key. While it is empty, TrustedKey returns ErrTrustKey
// and the puller refuses to apply any bundle (fail closed), so an unconfigured build can
// never be tricked into installing an unverifiable update.
const trustedPublicKeyBase64 = ""

// TrustedKey returns the compiled-in trusted public key, or ErrTrustKey if it is unset or
// malformed. A client with no trust root must never apply a bundle.
func TrustedKey() (ed25519.PublicKey, error) {
	return parsePublicKey(trustedPublicKeyBase64)
}

// parsePublicKey decodes a standard-base64 ed25519 public key, returning ErrTrustKey for an
// empty or structurally invalid value.
func parsePublicKey(encoded string) (ed25519.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, ErrTrustKey
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrTrustKey
	}
	return ed25519.PublicKey(raw), nil
}
