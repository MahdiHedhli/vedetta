// Package valid holds small, dependency-free format validators for wire
// metadata shared across the threat-network packages (ingest, auth, store).
// These enforce the pinned cross-module wire formats: batch_id / nonce are
// UUIDv4 and vedetta_version is strict semver. Keeping them here avoids
// duplicating the regexes and keeps a single source of truth for the formats.
package valid

import "regexp"

// uuidV4Re matches a canonical RFC 4122 version-4 UUID: the 13th hex digit is
// the version nibble ('4') and the 17th is the variant ('8','9','a','b').
var uuidV4Re = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// semverRe matches strict semver as pinned for vedetta_version:
// MAJOR.MINOR required, .PATCH optional, -prerelease optional. Numeric
// identifiers may not carry leading zeros; build metadata is not accepted.
var semverRe = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)(\.(0|[1-9]\d*))?(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// MaxSemverLen bounds an accepted vedetta_version string. The semver grammar's
// numeric identifiers are unbounded (\d*), so without an explicit length cap a
// multi-megabyte all-digits "version" (e.g. "1." + 3 MB of digits) matches the
// pattern and would be persisted (GHSA-7p69 over-long-field). A real semver is a
// handful of characters; 32 is generous. This guard is defense-in-depth beneath
// the caller's own field-length checks.
const MaxSemverLen = 32

// UUIDv4 reports whether s is a canonical version-4 UUID.
func UUIDv4(s string) bool { return uuidV4Re.MatchString(s) }

// Semver reports whether s is strict semver (MAJOR.MINOR[.PATCH][-prerelease])
// AND at most MaxSemverLen characters, so an over-long numeric identifier can
// never be accepted.
func Semver(s string) bool { return len(s) <= MaxSemverLen && semverRe.MatchString(s) }
