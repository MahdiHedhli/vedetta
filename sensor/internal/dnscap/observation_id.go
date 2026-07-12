package dnscap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

var observationSequence atomic.Uint64
var observationBootID = newObservationBootID()

// NewObservationID returns an opaque per-capture occurrence boundary. It is
// generated before query/response pairing and then copied into immutable HTTP
// batches, so transport retries cannot turn into new observations.
func NewObservationID() string {
	return fmt.Sprintf("dns-%s-%x", observationBootID, observationSequence.Add(1))
}

func newObservationBootID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	// crypto/rand failure is exceptionally rare. Keep the capture path alive and
	// make process restarts distinct without depending on timestamp precision
	// alone. The atomic suffix in NewObservationID distinguishes observations.
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), os.Getpid())
}
