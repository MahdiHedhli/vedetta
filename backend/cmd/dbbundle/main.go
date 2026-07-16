// Command dbbundle builds and signs a device-DB bundle. It computes a manifest over the
// given files and writes manifest.json plus manifest.json.sig (a detached ed25519
// signature) for upload as release assets. The release-db workflow runs it with the signing
// key supplied only as a CI secret; the key is never written to disk by this tool.
//
// Usage:
//
//	dbbundle -key <key|-> -release db-2026.07 -out dist \
//	    -file oui.csv=backend/internal/fingerprint/data/oui.csv
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/dbupdate"
)

type fileFlags []string

func (f *fileFlags) String() string     { return strings.Join(*f, ",") }
func (f *fileFlags) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dbbundle:", err)
		os.Exit(1)
	}
}

func run() error {
	var files fileFlags
	keyPath := flag.String("key", "", "path to a base64 ed25519 private key, or - for stdin")
	release := flag.String("release", "", "release tag, e.g. db-2026.07")
	out := flag.String("out", ".", "directory to write manifest.json and manifest.json.sig")
	generatedAt := flag.String("generated-at", "", "RFC3339 UTC timestamp (default: now)")
	flag.Var(&files, "file", "bundle entry as name=path (repeatable)")
	flag.Parse()

	if *release == "" {
		return errors.New("-release is required")
	}
	if len(files) == 0 {
		return errors.New("at least one -file is required")
	}

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}

	contents := make(map[string][]byte, len(files))
	for _, spec := range files {
		name, path, ok := strings.Cut(spec, "=")
		if !ok || name == "" || path == "" {
			return fmt.Errorf("invalid -file %q, want name=path", spec)
		}
		if _, duplicate := contents[name]; duplicate {
			return fmt.Errorf("duplicate -file name %q", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		contents[name] = data
	}

	ts := *generatedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	m, canonical, err := dbupdate.BuildManifest(contents, *release, ts)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, canonical)

	// Self-verify before emitting so CI never publishes a bundle the client would reject.
	pub := priv.Public().(ed25519.PublicKey)
	if err := dbupdate.VerifyManifest(m, sig, pub); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "manifest.json"), canonical, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "manifest.json.sig"), sig, 0o644); err != nil {
		return err
	}

	fmt.Printf("signed %d file(s) for release %s\n", len(m.Files), *release)
	fmt.Printf("public key (must match the client's trustedPublicKeyBase64): %s\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

// loadPrivateKey reads a base64 ed25519 private key from a file (or stdin for "-"),
// accepting either a 64-byte private key or a 32-byte seed.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key is not valid base64: %w", err)
	}
	switch len(decoded) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	default:
		return nil, fmt.Errorf("key must be a %d- or %d-byte ed25519 key, got %d bytes",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(decoded))
	}
}
