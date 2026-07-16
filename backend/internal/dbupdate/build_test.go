package dbupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"testing/fstest"
)

func TestBuildManifest_RoundTripsThroughVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"oui.csv":       []byte("prefix,vendor\nacbc32,\"Apple, Inc.\"\n"),
		"corpus/a.json": []byte(`{"ok":true}`),
	}
	m, canonical, err := BuildManifest(files, "db-2026.07", "2026-07-15T00:00:00Z")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// A bundle the builder produced must verify with the matching key...
	sig := ed25519.Sign(priv, canonical)
	fsys := fstest.MapFS{}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: data}
	}
	if err := VerifyBundle(fsys, m, sig, pub); err != nil {
		t.Fatalf("builder output failed client verification: %v", err)
	}

	// ...and the emitted manifest bytes must parse and re-canonicalize identically (so the
	// signed bytes are exactly what the client reconstructs).
	parsed, err := ParseManifest(canonical)
	if err != nil {
		t.Fatalf("emitted manifest did not parse: %v", err)
	}
	reCanonical, _ := parsed.Canonical()
	if string(reCanonical) != string(canonical) {
		t.Errorf("canonical bytes are not stable across a parse round-trip")
	}
}

func TestBuildManifest_Rejects(t *testing.T) {
	if _, _, err := BuildManifest(nil, "db", "t"); !errors.Is(err, ErrManifestEmpty) {
		t.Errorf("empty: got %v, want ErrManifestEmpty", err)
	}
	if _, _, err := BuildManifest(map[string][]byte{"../escape": {1}}, "db", "t"); !errors.Is(err, ErrManifestFile) {
		t.Errorf("traversal: got %v, want ErrManifestFile", err)
	}
	for _, name := range []string{manifestAssetName, signatureAssetName} {
		if _, _, err := BuildManifest(map[string][]byte{name: {1}}, "db-2026.07", "2026-07-15T00:00:00Z"); !errors.Is(err, ErrManifestFile) {
			t.Errorf("reserved name %q: got %v, want ErrManifestFile", name, err)
		}
	}
	if _, _, err := BuildManifest(map[string][]byte{"oui.csv": {1}}, "v0.1.0", "2026-07-15T00:00:00Z"); !errors.Is(err, ErrManifestMetadata) {
		t.Errorf("release metadata: got %v, want ErrManifestMetadata", err)
	}
	if _, _, err := BuildManifest(map[string][]byte{"oui.csv": {1}}, "db-2026.07", "not-a-time"); !errors.Is(err, ErrManifestMetadata) {
		t.Errorf("generated_at metadata: got %v, want ErrManifestMetadata", err)
	}
}
