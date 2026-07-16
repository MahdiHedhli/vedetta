package dbupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

var (
	// ErrTrustKey is returned when the compiled-in trust key is missing or malformed.
	ErrTrustKey = errors.New("dbupdate: trusted public key is not configured")
	// ErrSignatureInvalid is returned when the detached signature does not verify.
	ErrSignatureInvalid = errors.New("dbupdate: manifest signature is invalid")
	// ErrFileMissing is returned when a manifest-listed file is absent from the bundle.
	ErrFileMissing = errors.New("dbupdate: bundle file is missing")
	// ErrFileSizeMismatch is returned when a file's size differs from the manifest.
	ErrFileSizeMismatch = errors.New("dbupdate: bundle file size does not match the manifest")
	// ErrFileHashMismatch is returned when a file's SHA-256 differs from the manifest.
	ErrFileHashMismatch = errors.New("dbupdate: bundle file hash does not match the manifest")
)

// VerifyManifest checks the detached ed25519 signature over the manifest's canonical bytes
// against the trusted public key. It does not touch any file — call VerifyBundle for that.
func VerifyManifest(m *Manifest, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrTrustKey
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}
	canonical, err := m.Canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// entry returns the manifest entry for name, if present.
func (m *Manifest) entry(name string) (FileEntry, bool) {
	for _, f := range m.Files {
		if f.Name == name {
			return f, true
		}
	}
	return FileEntry{}, false
}

// verifyBytes confirms data matches the manifest entry for name (size then hash).
func (m *Manifest) verifyBytes(name string, data []byte) error {
	f, ok := m.entry(name)
	if !ok {
		return fmt.Errorf("%w: %s", ErrFileMissing, name)
	}
	if int64(len(data)) != f.Bytes {
		return fmt.Errorf("%w: %s", ErrFileSizeMismatch, name)
	}
	want, err := hex.DecodeString(f.SHA256)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFileHashMismatch, name)
	}
	sum := sha256.Sum256(data)
	// A content digest is not a secret, so a plain compare is fine here.
	if !bytes.Equal(sum[:], want) {
		return fmt.Errorf("%w: %s", ErrFileHashMismatch, name)
	}
	return nil
}

// VerifyBundle verifies a complete bundle: the manifest signature first, then that every
// file the manifest lists is present in fsys with a matching size and SHA-256. It returns
// on the first failure and never reports success for a partially-matching bundle, so a
// caller can install only after VerifyBundle returns nil.
func VerifyBundle(fsys fs.FS, m *Manifest, sig []byte, pub ed25519.PublicKey) error {
	if err := VerifyManifest(m, sig, pub); err != nil {
		return err
	}
	for _, f := range m.Files {
		data, err := readBundleFile(fsys, f)
		if err != nil {
			return err
		}
		if err := m.verifyBytes(f.Name, data); err != nil {
			return err
		}
	}
	return nil
}

// readBundleFile reads a single manifest-listed file, refusing to read more than the
// manifest's declared size (plus one byte, to detect an oversized file) or the hard cap.
func readBundleFile(fsys fs.FS, f FileEntry) ([]byte, error) {
	file, err := fsys.Open(f.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFileMissing, f.Name)
	}
	defer file.Close()

	limit := f.Bytes
	if limit < 0 || limit > maxBundleFileBytes {
		limit = maxBundleFileBytes
	}
	// +1 so a file longer than the manifest claims trips the size check rather than being
	// silently truncated to a matching length.
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("dbupdate: read %s: %w", f.Name, err)
	}
	return data, nil
}
