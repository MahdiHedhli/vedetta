package dbupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// releaseServer is an httptest release server that also counts asset downloads by name.
type releaseServer struct {
	*httptest.Server
	mu        sync.Mutex
	downloads map[string]int
}

func (rs *releaseServer) count(name string) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.downloads[name]
}

// newReleaseServer builds a signed bundle for dataFiles and serves it as a GitHub-style
// release (releases/latest metadata + asset downloads) signed with priv.
func newReleaseServer(t *testing.T, repo, tag string, dataFiles map[string]string, priv ed25519.PrivateKey) *releaseServer {
	t.Helper()
	m := &Manifest{SchemaVersion: manifestSchemaVersion, Release: tag, GeneratedAt: "2026-07-15T00:00:00Z"}
	for name, content := range dataFiles {
		sum := sha256.Sum256([]byte(content))
		m.Files = append(m.Files, FileEntry{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(content))})
	}
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	assets := map[string][]byte{
		manifestAssetName:  canonical,
		signatureAssetName: ed25519.Sign(priv, canonical),
	}
	for name, content := range dataFiles {
		assets[name] = []byte(content)
	}

	rs := &releaseServer{downloads: map[string]int{}}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+repo+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		rel := release{TagName: tag}
		for name, body := range assets {
			rel.Assets = append(rel.Assets, asset{Name: name, URL: srv.URL + "/download/" + name, Size: int64(len(body))})
		}
		_ = json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/download/")
		rs.mu.Lock()
		rs.downloads[name]++
		rs.mu.Unlock()
		body, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	srv = httptest.NewServer(mux)
	rs.Server = srv
	t.Cleanup(srv.Close)
	return rs
}

func TestUpdater_DisabledIsANoop(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	u, err := New(Config{InstallDir: t.TempDir(), PublicKey: pub}) // Enabled defaults false
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled Update: got %v, want ErrDisabled", err)
	}
}

func TestUpdater_HappyPathThenUpToDate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	files := map[string]string{"oui.csv": "prefix,vendor\nacbc32,Apple\n", "corpus/a.json": `{"ok":1}`}
	srv := newReleaseServer(t, repo, "db-2026.07", files, priv)
	dir := t.TempDir()
	u, err := New(Config{Enabled: true, Repo: repo, APIBaseURL: srv.URL, InstallDir: dir, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update(context.Background()); err != nil {
		t.Fatalf("update: %v", err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Errorf("installed %s = %q (err %v), want %q", name, got, err, want)
		}
	}
	if tag, _ := u.installedTag(); tag != "db-2026.07" {
		t.Errorf("recorded tag = %q, want db-2026.07", tag)
	}
	if err := u.Update(context.Background()); !errors.Is(err, errUpToDate) {
		t.Errorf("second update: got %v, want errUpToDate", err)
	}
}

func TestUpdater_BadSignatureKeepsLastGood(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader) // sign with the wrong key
	const repo = "owner/repo"
	srv := newReleaseServer(t, repo, "db-evil", map[string]string{"oui.csv": "NEW\n"}, wrongPriv)
	dir := t.TempDir()
	lastGood := filepath.Join(dir, "oui.csv")
	if err := os.WriteFile(lastGood, []byte("OLD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	u, err := New(Config{Enabled: true, Repo: repo, APIBaseURL: srv.URL, InstallDir: dir, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	err = u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "signature invalid, not downloading") {
		t.Fatalf("expected the manifest signature to be rejected before download, got %v", err)
	}
	// The forged manifest must be rejected BEFORE the data files are fetched, so a party who
	// can publish a release (but lacks the signing key) cannot drive a large download.
	if n := srv.count("oui.csv"); n != 0 {
		t.Errorf("data file was downloaded %d time(s) despite a bad manifest signature", n)
	}
	if got, _ := os.ReadFile(lastGood); string(got) != "OLD\n" {
		t.Errorf("last-good file was overwritten by an unverifiable update: %q", got)
	}
}

func TestUpdater_RejectsDisallowedAssetHost(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	srv := newReleaseServer(t, repo, "db-x", map[string]string{"oui.csv": "x"}, priv)
	u, err := New(Config{
		Enabled: true, Repo: repo, APIBaseURL: srv.URL, InstallDir: t.TempDir(),
		PublicKey: pub, AllowedHosts: []string{"example.invalid"}, // excludes the server host
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected an asset-host-not-allowed error, got %v", err)
	}
}

func TestNew_FailsClosedWithoutTrustRoot(t *testing.T) {
	// No PublicKey and the compiled-in placeholder is empty, so there is no trust root.
	if _, err := New(Config{InstallDir: t.TempDir()}); !errors.Is(err, ErrTrustKey) {
		t.Errorf("no trust root: got %v, want ErrTrustKey", err)
	}
}
