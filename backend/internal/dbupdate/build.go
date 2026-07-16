package dbupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// BuildManifest constructs a manifest for the given files (bundle-relative name -> content)
// and returns it together with its canonical, signable bytes. It is the builder-side
// counterpart to ParseManifest + VerifyBundle: a bundle whose manifest is produced here and
// signed over these bytes always verifies on the client, because both sides share this
// package's schema and canonical encoding.
func BuildManifest(files map[string][]byte, release, generatedAt string) (*Manifest, []byte, error) {
	if len(files) == 0 {
		return nil, nil, ErrManifestEmpty
	}
	if len(files) > maxManifestFiles {
		return nil, nil, fmt.Errorf("%w: %d", ErrManifestTooLarge, len(files))
	}
	m := &Manifest{SchemaVersion: manifestSchemaVersion, Release: release, GeneratedAt: generatedAt}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !isSafeName(name) {
			return nil, nil, fmt.Errorf("%w: %q", ErrManifestFile, name)
		}
		data := files[name]
		sum := sha256.Sum256(data)
		m.Files = append(m.Files, FileEntry{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))})
	}
	if err := validateManifestStructure(m); err != nil {
		return nil, nil, err
	}
	canonical, err := m.Canonical()
	if err != nil {
		return nil, nil, err
	}
	return m, canonical, nil
}
