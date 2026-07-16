package fingerprint

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const (
	// ouiDBOverrideEnv names an optional on-disk OUI table that supersedes the
	// compiled-in baseline. The Phase-3 signed-bundle puller installs a refreshed table
	// at this path.
	ouiDBOverrideEnv = "VEDETTA_OUI_DB_PATH"

	// minimumFullOUIRows keeps a truncated but syntactically valid override from
	// silently replacing the complete embedded registry with a handful of entries.
	// Keep this aligned with the updater's production OUI_MIN_ROWS default.
	minimumFullOUIRows = 30000
)

// embeddedOUICSV is the full IEEE MA-L (24-bit OUI) vendor table, refreshed monthly by
// the update-oui workflow. Shape: "prefix,vendor" with a header row (see data/oui.csv).
//
//go:embed data/oui.csv
var embeddedOUICSV []byte

// parseOUICSV parses a "prefix,vendor" CSV into a compact map of 24-bit MAC prefix
// (6 lowercase hex, no separators) -> vendor. The header row, malformed rows, and
// non-6-hex prefixes are skipped. Streaming, so it is unit-testable and bounded.
func parseOUICSV(r io.Reader) map[string]string {
	out := make(map[string]string, 40000)
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // tolerate ragged rows rather than aborting the whole table
	cr.ReuseRecord = true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip a malformed line, keep parsing the rest
		}
		if len(rec) < 2 {
			continue
		}
		prefix := strings.ToLower(strings.TrimSpace(rec[0]))
		vendor := strings.TrimSpace(rec[1])
		if !isHex6(prefix) || vendor == "" {
			continue // header ("prefix"), blank, or malformed
		}
		out[prefix] = vendor
	}
	return out
}

// isHex6 reports whether s is exactly 6 lowercase hex characters.
func isHex6(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// loadOUICSVFile parses an on-disk OUI CSV. It errors if the file can't be read or
// does not contain a plausibly complete registry, so a truncated/garbage override is
// rejected rather than silently erasing most of the embedded baseline's coverage.
func loadOUICSVFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := parseOUICSV(f)
	if len(m) < minimumFullOUIRows {
		return nil, fmt.Errorf("only %d usable OUI rows in %s; need at least %d", len(m), path, minimumFullOUIRows)
	}
	return m, nil
}

// loadIEEEOUI returns the IEEE OUI vendor table: the on-disk override
// (VEDETTA_OUI_DB_PATH) when present and valid, otherwise the compiled-in baseline.
func loadIEEEOUI() map[string]string {
	if path := strings.TrimSpace(os.Getenv(ouiDBOverrideEnv)); path != "" {
		if m, err := loadOUICSVFile(path); err == nil {
			log.Printf("[fingerprint] loaded %d OUI entries from override %s", len(m), path)
			return m
		} else if errors.Is(err, os.ErrNotExist) {
			// A configured generation path is normally absent until the first opt-in
			// update. Quietly use the embedded baseline during that expected state.
		} else {
			log.Printf("[fingerprint] OUI override %s unusable (%v); using embedded baseline", path, err)
		}
	}
	return parseOUICSV(bytes.NewReader(embeddedOUICSV))
}

// ReloadIEEEOUI validates the currently configured override and atomically publishes it
// for future lookups. Unlike initial startup, an explicitly configured but unusable file
// is an error: the signed updater uses this as its post-switch acceptance check and rolls
// the generation pointer back rather than silently claiming an update while using fallback.
func ReloadIEEEOUI() error {
	path := strings.TrimSpace(os.Getenv(ouiDBOverrideEnv))
	var next map[string]string
	if path == "" {
		next = parseOUICSV(bytes.NewReader(embeddedOUICSV))
	} else {
		loaded, err := loadOUICSVFile(path)
		if err != nil {
			return fmt.Errorf("reload OUI override %s: %w", path, err)
		}
		next = loaded
	}
	ieeeOUIMu.Lock()
	ieeeOUI = next
	ieeeOUIMu.Unlock()
	log.Printf("[fingerprint] reloaded %d OUI entries", len(next))
	return nil
}
