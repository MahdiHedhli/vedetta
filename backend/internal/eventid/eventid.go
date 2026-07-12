// Package eventid derives replay-stable event UUIDs at ingestion boundaries.
//
// Upstream sources do not all provide a durable record identifier. A random ID
// makes an HTTP/poller retry look like a new event, which can inflate both raw
// event and finding counts after a partial batch failure. Deterministic IDs make
// SQLite's event primary key the idempotency boundary without treating an ID as
// authentication or device identity.
package eventid

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

const schemaVersion = "vedetta-event-id-v1"

// Deterministic returns an RFC 4122-compatible, version-8 UUID derived from the
// adapter, stable source identity, upstream timestamp, and normalized record
// material. material should be a struct or map containing only upstream-stable
// values. encoding/json sorts map keys, so JSON object key order cannot change
// the result.
//
// A zero timestamp is represented explicitly. That is the best possible replay
// boundary for legacy records which carry neither an event ID nor a timestamp;
// two otherwise identical such records are indistinguishable upstream.
func Deterministic(adapter, sourceIdentity string, timestamp time.Time, material any) string {
	canonical, err := json.Marshal(material)
	if err != nil {
		// All current callers pass JSON-safe structs/maps. Keep this helper total in
		// case a future adapter accidentally includes an unsupported value.
		canonical = []byte(`null`)
	}
	timestampText := ""
	if !timestamp.IsZero() {
		timestampText = timestamp.UTC().Format(time.RFC3339Nano)
	}
	seed := strings.Join([]string{
		schemaVersion,
		strings.TrimSpace(strings.ToLower(adapter)),
		strings.TrimSpace(sourceIdentity),
		timestampText,
		string(canonical),
	}, "\x00")
	sum := sha256.Sum256([]byte(seed))
	var id uuid.UUID
	copy(id[:], sum[:16])
	// RFC 9562 version 8 is reserved for application-defined UUID layouts.
	id[6] = (id[6] & 0x0f) | 0x80
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}
