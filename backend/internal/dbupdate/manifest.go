// Package dbupdate verifies and applies signed device-database bundles — the IEEE OUI
// table today, the fingerprint-corpus snapshot later. A bundle is a set of data files, a
// manifest.json pinning each file to its SHA-256, and a detached ed25519 signature over
// the manifest's canonical bytes. The signing key lives only as a CI secret; clients trust
// a compiled-in public key. A bundle is applied only when the signature verifies AND every
// listed file's size and hash match — verification always precedes installation.
package dbupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// manifestSchemaVersion is the on-disk manifest schema this client understands. Bump it
// only for breaking changes; the verifier refuses versions it does not recognize.
const manifestSchemaVersion = 1

// maxManifestFiles bounds a manifest so a malformed or hostile one cannot exhaust memory
// on the Pi-4 floor. The real bundle carries a handful of files (OUI table + corpus parts).
const maxManifestFiles = 64

var (
	// ErrManifestSchema is returned for an unrecognized schema version.
	ErrManifestSchema = errors.New("dbupdate: unsupported manifest schema version")
	// ErrManifestEmpty is returned when a manifest lists no files.
	ErrManifestEmpty = errors.New("dbupdate: manifest lists no files")
	// ErrManifestTooLarge is returned when a manifest lists more files than allowed.
	ErrManifestTooLarge = errors.New("dbupdate: manifest lists too many files")
	// ErrManifestFile is returned for a malformed file entry (name, hash, or size).
	ErrManifestFile = errors.New("dbupdate: manifest file entry is malformed")
	// ErrManifestDuplicate is returned when a file name appears more than once.
	ErrManifestDuplicate = errors.New("dbupdate: manifest lists a duplicate file name")
)

// sha256HexRE matches a lowercase hex SHA-256 digest.
var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// safeNameRE matches a bundle-relative file name: one or more path segments of
// [A-Za-z0-9._-], no separators that could escape the install directory.
var safeNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

// FileEntry pins one bundle file to its SHA-256 and size.
type FileEntry struct {
	Name   string `json:"name"`   // bundle-relative path, e.g. "oui.csv"
	SHA256 string `json:"sha256"` // lowercase hex SHA-256 of the file bytes
	Bytes  int64  `json:"bytes"`  // file size in bytes (a cheap pre-hash bound)
}

// Manifest describes the contents of a signed device-DB bundle.
type Manifest struct {
	SchemaVersion int         `json:"schema_version"`
	Release       string      `json:"release"`      // release tag, e.g. "db-2026.07"
	GeneratedAt   string      `json:"generated_at"` // RFC3339 UTC, set by the builder
	Files         []FileEntry `json:"files"`
}

// isSafeName reports whether name is a bundle-relative path that cannot escape the install
// directory: no absolute paths, no "." / ".." segments, no backslashes.
func isSafeName(name string) bool {
	if !safeNameRE.MatchString(name) {
		return false
	}
	for _, seg := range bytes.Split([]byte(name), []byte("/")) {
		if string(seg) == "." || string(seg) == ".." {
			return false
		}
	}
	return true
}

// Canonical returns the deterministic JSON encoding that is signed and verified. Files are
// sorted by name so the bytes are stable regardless of the order the builder emitted them.
func (m *Manifest) Canonical() ([]byte, error) {
	out := *m
	out.Files = append([]FileEntry(nil), m.Files...)
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Name < out.Files[j].Name })
	return json.Marshal(&out)
}

// ParseManifest decodes and structurally validates a manifest. It does NOT check the
// signature (see VerifyManifest) — it only guarantees the manifest is well-formed and
// every file entry is safe to act on.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("dbupdate: decode manifest: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("dbupdate: manifest has trailing data")
	}
	if m.SchemaVersion != manifestSchemaVersion {
		return nil, fmt.Errorf("%w: %d", ErrManifestSchema, m.SchemaVersion)
	}
	if len(m.Files) == 0 {
		return nil, ErrManifestEmpty
	}
	if len(m.Files) > maxManifestFiles {
		return nil, fmt.Errorf("%w: %d", ErrManifestTooLarge, len(m.Files))
	}
	seen := make(map[string]struct{}, len(m.Files))
	for _, f := range m.Files {
		if !isSafeName(f.Name) || !sha256HexRE.MatchString(f.SHA256) || f.Bytes < 0 {
			return nil, fmt.Errorf("%w: %q", ErrManifestFile, f.Name)
		}
		if _, dup := seen[f.Name]; dup {
			return nil, fmt.Errorf("%w: %q", ErrManifestDuplicate, f.Name)
		}
		seen[f.Name] = struct{}{}
	}
	return &m, nil
}
