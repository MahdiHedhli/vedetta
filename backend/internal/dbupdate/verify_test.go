package dbupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// buildSignedBundle returns a manifest, its detached signature, the signing public key, and
// a filesystem containing the listed files — all internally consistent.
func buildSignedBundle(t *testing.T, files map[string]string) (*Manifest, []byte, ed25519.PublicKey, fstest.MapFS) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fsys := fstest.MapFS{}
	m := &Manifest{SchemaVersion: manifestSchemaVersion, Release: "db-2026.07", GeneratedAt: "2026-07-15T00:00:00Z"}
	for name, content := range files {
		sum := sha256.Sum256([]byte(content))
		m.Files = append(m.Files, FileEntry{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(content))})
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return m, ed25519.Sign(priv, canonical), pub, fsys
}

func TestVerifyBundle_HappyPath(t *testing.T) {
	m, sig, pub, fsys := buildSignedBundle(t, map[string]string{
		"oui.csv":       "prefix,vendor\nacbc32,\"Apple, Inc.\"\n",
		"corpus/x.json": `{"ok":true}`,
	})
	if err := VerifyBundle(fsys, m, sig, pub); err != nil {
		t.Fatalf("expected a valid bundle to verify, got %v", err)
	}
}

func TestVerifyManifest_Tampering(t *testing.T) {
	m, sig, pub, _ := buildSignedBundle(t, map[string]string{"oui.csv": "data"})

	// A different key must not verify.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyManifest(m, sig, otherPub); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("wrong key: got %v, want ErrSignatureInvalid", err)
	}

	// Mutating a signed field must invalidate the signature.
	tampered := *m
	tampered.Release = "db-evil"
	if err := VerifyManifest(&tampered, sig, pub); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered manifest: got %v, want ErrSignatureInvalid", err)
	}

	// Mutating a file's expected hash must invalidate the signature.
	swapped := *m
	swapped.Files = append([]FileEntry(nil), m.Files...)
	swapped.Files[0].SHA256 = hex.EncodeToString(make([]byte, 32))
	if err := VerifyManifest(&swapped, sig, pub); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("swapped hash: got %v, want ErrSignatureInvalid", err)
	}

	// A malformed signature/key fails closed.
	if err := VerifyManifest(m, sig[:10], pub); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("short sig: got %v, want ErrSignatureInvalid", err)
	}
	if err := VerifyManifest(m, sig, ed25519.PublicKey{1, 2, 3}); !errors.Is(err, ErrTrustKey) {
		t.Errorf("bad key length: got %v, want ErrTrustKey", err)
	}
}

func TestVerifyBundle_FileMismatches(t *testing.T) {
	base := map[string]string{"oui.csv": "prefix,vendor\n"}

	t.Run("hash mismatch", func(t *testing.T) {
		m, sig, pub, fsys := buildSignedBundle(t, base)
		// Same byte length as the original so the size check passes and the hash check is
		// what fires (uppercase VENDOR vs lowercase vendor).
		fsys["oui.csv"] = &fstest.MapFile{Data: []byte("prefix,VENDOR\n")}
		if err := VerifyBundle(fsys, m, sig, pub); !errors.Is(err, ErrFileHashMismatch) {
			t.Errorf("got %v, want ErrFileHashMismatch", err)
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		m, sig, pub, fsys := buildSignedBundle(t, base)
		fsys["oui.csv"] = &fstest.MapFile{Data: []byte("prefix,vendor\nextra-bytes")}
		if err := VerifyBundle(fsys, m, sig, pub); !errors.Is(err, ErrFileSizeMismatch) {
			t.Errorf("got %v, want ErrFileSizeMismatch", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		m, sig, pub, fsys := buildSignedBundle(t, base)
		delete(fsys, "oui.csv")
		if err := VerifyBundle(fsys, m, sig, pub); !errors.Is(err, ErrFileMissing) {
			t.Errorf("got %v, want ErrFileMissing", err)
		}
	})
}

func TestManifest_CanonicalIsOrderIndependent(t *testing.T) {
	a := &Manifest{SchemaVersion: 1, Files: []FileEntry{{Name: "b", SHA256: hexZero(), Bytes: 1}, {Name: "a", SHA256: hexZero(), Bytes: 2}}}
	b := &Manifest{SchemaVersion: 1, Files: []FileEntry{{Name: "a", SHA256: hexZero(), Bytes: 2}, {Name: "b", SHA256: hexZero(), Bytes: 1}}}
	ca, _ := a.Canonical()
	cb, _ := b.Canonical()
	if string(ca) != string(cb) {
		t.Errorf("canonical form must not depend on file order:\n a=%s\n b=%s", ca, cb)
	}
}

func TestParseManifest(t *testing.T) {
	valid := `{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"oui.csv","sha256":"` + hexZero() + `","bytes":10}]}`
	if _, err := ParseManifest([]byte(valid)); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	cases := map[string]struct {
		json string
		want error
	}{
		"unknown schema":  {`{"schema_version":9,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"a","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestSchema},
		"empty files":     {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[]}`, ErrManifestEmpty},
		"duplicate name":  {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"a","sha256":"` + hexZero() + `","bytes":1},{"name":"a","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestDuplicate},
		"path traversal":  {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"../etc/passwd","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestFile},
		"absolute path":   {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"/etc/passwd","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestFile},
		"manifest asset":  {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"manifest.json","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestFile},
		"signature asset": {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"manifest.json.sig","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestFile},
		"non-hex sha":     {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"a","sha256":"nothex","bytes":1}]}`, ErrManifestFile},
		"negative bytes":  {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"a","sha256":"` + hexZero() + `","bytes":-1}]}`, ErrManifestFile},
		"oversized file":  {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"a","sha256":"` + hexZero() + `","bytes":67108865}]}`, ErrManifestFile},
		"oversized total": {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"a","sha256":"` + hexZero() + `","bytes":67108864},{"name":"b","sha256":"` + hexZero() + `","bytes":67108864},{"name":"c","sha256":"` + hexZero() + `","bytes":67108864},{"name":"d","sha256":"` + hexZero() + `","bytes":67108864},{"name":"e","sha256":"` + hexZero() + `","bytes":1}]}`, ErrManifestTooLarge},
		"unknown field":   {`{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","extra":true,"files":[{"name":"a","sha256":"` + hexZero() + `","bytes":1}]}`, nil}, // decode error, not a sentinel
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseManifest([]byte(c.json))
			if err == nil {
				t.Fatalf("expected an error")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseManifest_RejectsTrailingJSONAndBadMetadata(t *testing.T) {
	valid := `{"schema_version":1,"release":"db-2026.07","generated_at":"2026-07-15T00:00:00Z","files":[{"name":"oui.csv","sha256":"` + hexZero() + `","bytes":10}]}`
	if _, err := ParseManifest([]byte(valid + " \n\t")); err != nil {
		t.Fatalf("trailing whitespace rejected: %v", err)
	}
	if _, err := ParseManifest([]byte(valid + `{}`)); err == nil {
		t.Fatal("trailing JSON value accepted")
	}
	for _, bad := range []string{
		strings.Replace(valid, "db-2026.07", "v0.1.0", 1),
		strings.Replace(valid, "db-2026.07", "db-2026.02.31", 1),
		strings.Replace(valid, "db-2026.07", "db-2026.07.15.01", 1),
		strings.Replace(valid, "2026-07-15T00:00:00Z", "2026-07-15T00:00:00-04:00", 1),
	} {
		if _, err := ParseManifest([]byte(bad)); !errors.Is(err, ErrManifestMetadata) {
			t.Errorf("bad metadata: got %v, want ErrManifestMetadata", err)
		}
	}
}

func TestDBReleaseVersionOrdering(t *testing.T) {
	ordered := []string{"db-2026.07", "db-2026.07.01", "db-2026.07.01.1", "db-2026.08", "db-2027.01"}
	for i := 1; i < len(ordered); i++ {
		previous, okPrevious := parseDBReleaseVersion(ordered[i-1])
		current, okCurrent := parseDBReleaseVersion(ordered[i])
		if !okPrevious || !okCurrent || compareDBReleaseVersion(previous, current) >= 0 {
			t.Fatalf("expected %s < %s", ordered[i-1], ordered[i])
		}
	}
}

func TestParsePublicKey_FailsClosedAndValidates(t *testing.T) {
	if _, err := parsePublicKey(""); !errors.Is(err, ErrTrustKey) {
		t.Errorf("empty trust key: got %v, want ErrTrustKey", err)
	}
	// A well-formed key round-trips.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := parsePublicKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || !got.Equal(pub) {
		t.Errorf("round-trip: got (%x, %v), want the same key", got, err)
	}
	if _, err := parsePublicKey("!!!not-base64!!!"); !errors.Is(err, ErrTrustKey) {
		t.Errorf("malformed key: got %v, want ErrTrustKey", err)
	}
}

func hexZero() string { return hex.EncodeToString(make([]byte, 32)) }
