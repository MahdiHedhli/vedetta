// Command corpuscheck validates that a public device-corpus snapshot is accepted by the
// Core runtime parser. It is used as a release gate before corpus.json is signed.
package main

import (
	"fmt"
	"os"

	"github.com/vedetta-network/vedetta/backend/internal/corpusmatch"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: corpuscheck <corpus.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err == nil {
		_, err = corpusmatch.ParseSnapshot(data)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpuscheck: %v\n", err)
		os.Exit(1)
	}
}
