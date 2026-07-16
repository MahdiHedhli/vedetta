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
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// manifestSchemaVersion is the on-disk manifest schema this client understands. Bump it
// only for breaking changes; the verifier refuses versions it does not recognize.
const manifestSchemaVersion = 1

// maxManifestFiles bounds a manifest so a malformed or hostile one cannot exhaust memory
// on the Pi-4 floor. The real bundle carries a handful of files (OUI table + corpus parts).
const maxManifestFiles = 64

// maxBundleFileBytes is the single per-file contract shared by manifest parsing,
// bundle construction, downloading, and verification.
const maxBundleFileBytes = 64 << 20 // 64 MiB

// maxBundleTotalBytes caps the summed declared size of a bundle. It bounds how much a
// manifest can make the client download even before per-file limits apply, so a hostile
// (or accidental) manifest cannot direct a multi-gigabyte download at the Pi-4 floor.
const maxBundleTotalBytes = 256 << 20 // 256 MiB

var (
	// ErrManifestSchema is returned for an unrecognized schema version.
	ErrManifestSchema = errors.New("dbupdate: unsupported manifest schema version")
	// ErrManifestEmpty is returned when a manifest lists no files.
	ErrManifestEmpty = errors.New("dbupdate: manifest lists no files")
	// ErrManifestTooLarge is returned when file count or aggregate bytes exceed a cap.
	ErrManifestTooLarge = errors.New("dbupdate: manifest lists too many files")
	// ErrManifestFile is returned for a malformed file entry (name, hash, or size).
	ErrManifestFile = errors.New("dbupdate: manifest file entry is malformed")
	// ErrManifestDuplicate is returned when a file name appears more than once.
	ErrManifestDuplicate = errors.New("dbupdate: manifest lists a duplicate file name")
	// ErrManifestMetadata is returned when release/version metadata is malformed.
	ErrManifestMetadata = errors.New("dbupdate: manifest release metadata is malformed")
)

// sha256HexRE matches a lowercase hex SHA-256 digest.
var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// safeNameRE matches a bundle-relative file name: one or more path segments of
// [A-Za-z0-9._-], no separators that could escape the install directory.
var safeNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

// Device-DB tags are monotonically ordered calendar versions. Optional day and
// revision components allow more than one release per month without making
// ordering dependent on GitHub publication time.
var dbReleaseTagRE = regexp.MustCompile(`^db-([0-9]{4})\.([0-9]{2})(?:\.([0-9]{2}))?(?:\.([0-9]+))?$`)

type dbReleaseVersion struct {
	year, month, day, revision int
}

func parseDBReleaseVersion(tag string) (dbReleaseVersion, bool) {
	trimmed := strings.TrimSpace(tag)
	if tag != trimmed {
		return dbReleaseVersion{}, false
	}
	match := dbReleaseTagRE.FindStringSubmatch(trimmed)
	if match == nil {
		return dbReleaseVersion{}, false
	}
	values := [4]int{}
	for i := range values {
		if match[i+1] == "" {
			continue
		}
		value, err := strconv.Atoi(match[i+1])
		if err != nil {
			return dbReleaseVersion{}, false
		}
		values[i] = value
	}
	if values[0] < 2000 || values[1] < 1 || values[1] > 12 ||
		(match[3] != "" && (values[2] < 1 || values[2] > 31)) ||
		(match[4] != "" && (values[3] < 1 || (len(match[4]) > 1 && match[4][0] == '0'))) {
		return dbReleaseVersion{}, false
	}
	if match[3] != "" {
		date := time.Date(values[0], time.Month(values[1]), values[2], 0, 0, 0, 0, time.UTC)
		if date.Year() != values[0] || int(date.Month()) != values[1] || date.Day() != values[2] {
			return dbReleaseVersion{}, false
		}
	}
	return dbReleaseVersion{year: values[0], month: values[1], day: values[2], revision: values[3]}, true
}

func compareDBReleaseVersion(a, b dbReleaseVersion) int {
	av := [...]int{a.year, a.month, a.day, a.revision}
	bv := [...]int{b.year, b.month, b.day, b.revision}
	for i := range av {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

func parseGeneratedAt(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	_, offset := parsed.Zone()
	return parsed.UTC(), offset == 0
}

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
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("dbupdate: manifest has trailing data")
		}
		return nil, fmt.Errorf("dbupdate: decode trailing manifest data: %w", err)
	}
	if err := validateManifestStructure(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func validateManifestStructure(m *Manifest) error {
	if m.SchemaVersion != manifestSchemaVersion {
		return fmt.Errorf("%w: %d", ErrManifestSchema, m.SchemaVersion)
	}
	if _, ok := parseDBReleaseVersion(m.Release); !ok {
		return fmt.Errorf("%w: release %q", ErrManifestMetadata, m.Release)
	}
	if _, ok := parseGeneratedAt(m.GeneratedAt); !ok {
		return fmt.Errorf("%w: generated_at %q", ErrManifestMetadata, m.GeneratedAt)
	}
	if len(m.Files) == 0 {
		return ErrManifestEmpty
	}
	if len(m.Files) > maxManifestFiles {
		return fmt.Errorf("%w: %d", ErrManifestTooLarge, len(m.Files))
	}
	seen := make(map[string]struct{}, len(m.Files))
	var total int64
	for _, f := range m.Files {
		if !isSafeName(f.Name) || !sha256HexRE.MatchString(f.SHA256) || f.Bytes < 0 || f.Bytes > maxBundleFileBytes {
			return fmt.Errorf("%w: %q", ErrManifestFile, f.Name)
		}
		if _, dup := seen[f.Name]; dup {
			return fmt.Errorf("%w: %q", ErrManifestDuplicate, f.Name)
		}
		seen[f.Name] = struct{}{}
		total += f.Bytes // each f.Bytes <= cap and <= 64 files, so this cannot overflow int64
	}
	if total > maxBundleTotalBytes {
		return fmt.Errorf("%w: %d bytes total", ErrManifestTooLarge, total)
	}
	return nil
}
