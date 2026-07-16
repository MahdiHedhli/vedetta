// Command corpuscheck applies the canonical threat-network publication privacy and
// structural gate to exact snapshot bytes before a device-DB release signs them.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

const maxSnapshotBytes = 32 << 20

func validateSnapshot(data []byte) error {
	if len(data) > maxSnapshotBytes {
		return fmt.Errorf("snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var snapshot corpus.PublicSnapshot
	if err := dec.Decode(&snapshot); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("snapshot contains trailing JSON")
		}
		return fmt.Errorf("decode trailing snapshot data: %w", err)
	}
	return corpus.ValidatePublicSnapshot(snapshot)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: corpuscheck <corpus.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err == nil {
		err = validateSnapshot(data)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpuscheck: %v\n", err)
		os.Exit(1)
	}
}
