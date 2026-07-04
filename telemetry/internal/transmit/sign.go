// Package transmit handles reporter registration, batch signing, transmission
// with backoff, and the bounded on-disk spool. It is the only component that
// talks to the threat network.
package transmit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignatureInput is the canonical material signed per contract §1.
type SignatureInput struct {
	Timestamp string // unix-seconds as string
	Nonce     string // random UUID v4
	Body      []byte // UNCOMPRESSED batch JSON
}

// bodyHashHex returns sha256hex(uncompressed_body).
func bodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalString builds the signing string:
//
//	timestamp + "\n" + nonce + "\n" + sha256hex(uncompressed_body)
func CanonicalString(in SignatureInput) string {
	return in.Timestamp + "\n" + in.Nonce + "\n" + bodyHashHex(in.Body)
}

// Sign computes hex(HMAC-SHA256(secret, canonical string)) per contract §1.
func Sign(secret []byte, in SignatureInput) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(CanonicalString(in)))
	return hex.EncodeToString(m.Sum(nil))
}
