// Package idgen produces random UUID v4 values and nonces using crypto/rand.
// A tiny stdlib-only helper avoids pulling a UUID dependency into the telemetry
// module.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// UUIDv4 returns a random RFC 4122 version-4 UUID string.
func UUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic; panic rather than emit a weak ID.
		panic(fmt.Sprintf("idgen: crypto/rand failed: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
