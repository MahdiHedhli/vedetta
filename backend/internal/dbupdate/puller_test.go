package dbupdate

import (
	"bytes"
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
	"time"
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
// release (release-list metadata + asset downloads) signed with priv.
func newReleaseServer(t *testing.T, repo, tag string, dataFiles map[string]string, priv ed25519.PrivateKey, additional ...release) *releaseServer {
	return newReleaseServerWithManifestTag(t, repo, tag, tag, dataFiles, priv, additional...)
}

func newReleaseServerWithManifestTag(t *testing.T, repo, tag, manifestTag string, dataFiles map[string]string, priv ed25519.PrivateKey, additional ...release) *releaseServer {
	t.Helper()
	m := &Manifest{SchemaVersion: manifestSchemaVersion, Release: manifestTag, GeneratedAt: "2026-07-15T00:00:00Z"}
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
	mux.HandleFunc("/repos/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		rel := release{TagName: tag}
		for name, body := range assets {
			rel.Assets = append(rel.Assets, asset{Name: name, URL: srv.URL + "/download/" + name, Size: int64(len(body))})
		}
		releases := append([]release{rel}, additional...)
		_ = json.NewEncoder(w).Encode(releases)
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
	dir := filepath.Join(t.TempDir(), "current")
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
	srv := newReleaseServer(t, repo, "db-2026.08", map[string]string{"oui.csv": "NEW\n"}, wrongPriv)
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
	srv := newReleaseServer(t, repo, "db-2026.09", map[string]string{"oui.csv": "x"}, priv)
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

func TestUpdater_SelectsHighestDBReleaseAndIgnoresSoftwareRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	srv := newReleaseServer(t, repo, "db-2026.08", map[string]string{"oui.csv": "new\n"}, priv,
		release{TagName: "v0.1.0-beta.4"},
		release{TagName: "db-2026.07"},
		release{TagName: "db-2026.09", Draft: true},
		release{TagName: "db-2026.10", Prerelease: true},
	)
	dir := filepath.Join(t.TempDir(), "current")
	u, err := New(Config{Enabled: true, Repo: repo, APIBaseURL: srv.URL, InstallDir: dir, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update(context.Background()); err != nil {
		t.Fatalf("update: %v", err)
	}
	if tag, err := u.installedTag(); err != nil || tag != "db-2026.08" {
		t.Fatalf("installed tag = %q, %v; want db-2026.08", tag, err)
	}
}

func TestUpdater_RejectsSignedManifestFromDifferentRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	srv := newReleaseServerWithManifestTag(t, repo, "db-2026.08", "db-2026.07",
		map[string]string{"oui.csv": "replayed\n"}, priv)
	u, err := New(Config{Enabled: true, Repo: repo, APIBaseURL: srv.URL,
		InstallDir: filepath.Join(t.TempDir(), "current"), PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	err = u.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not match GitHub tag") {
		t.Fatalf("tag replay: got %v", err)
	}
	if got := srv.count("oui.csv"); got != 0 {
		t.Fatalf("downloaded data %d time(s) before rejecting tag replay", got)
	}
}

func TestUpdater_RefusesDowngrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	dir := filepath.Join(t.TempDir(), "current")
	newer := newReleaseServer(t, repo, "db-2026.08", map[string]string{"oui.csv": "new\n"}, priv)
	u, err := New(Config{Enabled: true, Repo: repo, APIBaseURL: newer.URL, InstallDir: dir, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	older := newReleaseServer(t, repo, "db-2026.07", map[string]string{"oui.csv": "old\n"}, priv)
	u, err = New(Config{Enabled: true, Repo: repo, APIBaseURL: older.URL, InstallDir: dir, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Update(context.Background()); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade: got %v, want ErrDowngrade", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "oui.csv")); string(got) != "new\n" {
		t.Fatalf("downgrade changed installed data: %q", got)
	}
}

func TestUpdater_GenerationSwitchRemovesStaleFiles(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	dir := filepath.Join(t.TempDir(), "current")
	first := newReleaseServer(t, repo, "db-2026.07", map[string]string{"oui.csv": "one\n", "corpus/stale.json": "{}"}, priv)
	u, _ := New(Config{Enabled: true, Repo: repo, APIBaseURL: first.URL, InstallDir: dir, PublicKey: pub})
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := newReleaseServer(t, repo, "db-2026.08", map[string]string{"oui.csv": "two\n"}, priv)
	u, _ = New(Config{Enabled: true, Repo: repo, APIBaseURL: second.URL, InstallDir: dir, PublicKey: pub})
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "corpus/stale.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale file survived generation switch: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "oui.csv")); string(got) != "two\n" {
		t.Fatalf("new generation not active: %q", got)
	}
}

func TestInstallGeneration_FailureLeavesOldPointerUntouched(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	dir := filepath.Join(t.TempDir(), "current")
	first := newReleaseServer(t, repo, "db-2026.07", map[string]string{"oui.csv": "old\n"}, priv)
	u, _ := New(Config{Enabled: true, Repo: repo, APIBaseURL: first.URL, InstallDir: dir, PublicKey: pub})
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"oui.csv": []byte("new\n"), "corpus/required.json": []byte("{}")}
	manifest, _, err := BuildManifest(files, "db-2026.08", "2026-07-15T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	if err := writeStaged(staging, "oui.csv", files["oui.csv"]); err != nil {
		t.Fatal(err)
	}
	if err := u.installGeneration(manifest, staging); err == nil {
		t.Fatal("incomplete staged generation installed")
	}
	if tag, _ := u.installedTag(); tag != "db-2026.07" {
		t.Fatalf("failed install changed tag to %q", tag)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "oui.csv")); string(got) != "old\n" {
		t.Fatalf("failed install changed data: %q", got)
	}
}

func TestUpdater_RollsBackWhenConsumerRejectsGeneration(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	dir := filepath.Join(t.TempDir(), "current")
	first := newReleaseServer(t, repo, "db-2026.07", map[string]string{"oui.csv": "one\n"}, priv)
	u, _ := New(Config{Enabled: true, Repo: repo, APIBaseURL: first.URL, InstallDir: dir, PublicKey: pub})
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := newReleaseServer(t, repo, "db-2026.08", map[string]string{"oui.csv": "two\n"}, priv)
	u, _ = New(Config{Enabled: true, Repo: repo, APIBaseURL: second.URL, InstallDir: dir, PublicKey: pub,
		OnInstalled: func() error { return errors.New("bad corpus") }})
	if err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("consumer rejection: got %v", err)
	}
	if tag, _ := u.installedTag(); tag != "db-2026.07" {
		t.Fatalf("rollback tag = %q", tag)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "oui.csv")); string(got) != "one\n" {
		t.Fatalf("rollback data = %q", got)
	}
}

func TestNew_DoesNotMutateCallerHTTPClient(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	originalRedirect := func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	client := &http.Client{Timeout: time.Second, CheckRedirect: originalRedirect}
	_, err := New(Config{InstallDir: t.TempDir(), PublicKey: pub, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if client.CheckRedirect == nil {
		t.Fatal("caller's CheckRedirect was cleared")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if got := client.CheckRedirect(request, nil); !errors.Is(got, http.ErrUseLastResponse) {
		t.Fatalf("caller's CheckRedirect was replaced: %v", got)
	}
}

func TestNew_DefaultsUnboundedCallerHTTPTimeout(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			client := &http.Client{Timeout: timeout}
			u, err := New(Config{InstallDir: t.TempDir(), PublicKey: pub, HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			if client.Timeout != timeout {
				t.Fatalf("caller's timeout mutated from %s to %s", timeout, client.Timeout)
			}
			if u.client.Timeout != defaultHTTPTimeout {
				t.Fatalf("updater timeout = %s, want %s", u.client.Timeout, defaultHTTPTimeout)
			}
		})
	}
}

func TestNew_CopiesCallerPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	want := append(ed25519.PublicKey(nil), pub...)
	u, err := New(Config{InstallDir: t.TempDir(), PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	pub[0] ^= 0xff
	if !bytes.Equal(u.cfg.PublicKey, want) {
		t.Fatal("caller mutation changed updater trust root")
	}
}

func TestNew_RejectsRepoDotSegments(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, repo := range []string{"../repo", "./repo", "owner/..", "owner/."} {
		t.Run(repo, func(t *testing.T) {
			if _, err := New(Config{Repo: repo, InstallDir: t.TempDir(), PublicKey: pub}); err == nil {
				t.Fatalf("accepted unsafe Repo %q", repo)
			}
		})
	}
	if _, err := New(Config{Repo: "owner.with-dots/repo_name-1", InstallDir: t.TempDir(), PublicKey: pub}); err != nil {
		t.Fatalf("rejected valid Repo: %v", err)
	}
}

func TestActivateConsumerEnforcesManagedPointerState(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	u, err := New(Config{InstallDir: filepath.Join(root, "current"), PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	activations := 0
	activate := func(path string) error {
		if path != u.InstallDir() {
			t.Fatalf("activation path = %q, want %q", path, u.InstallDir())
		}
		activations++
		return nil
	}

	if err := u.ActivateConsumer(activate); err != nil {
		t.Fatalf("absent first-run pointer: %v", err)
	}
	if err := os.Mkdir(u.InstallDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := u.ActivateConsumer(activate); err == nil {
		t.Fatal("accepted a precreated real install directory")
	}
	if err := os.Remove(u.InstallDir()); err != nil {
		t.Fatal(err)
	}

	danglingTarget := ".current-release-db-2026.07-dangling"
	if err := os.Symlink(danglingTarget, u.InstallDir()); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := u.ActivateConsumer(activate); err == nil {
		t.Fatal("accepted a dangling managed pointer")
	}
	if err := os.Remove(u.InstallDir()); err != nil {
		t.Fatal(err)
	}

	validTarget := ".current-release-db-2026.07-valid"
	validGeneration := filepath.Join(root, validTarget)
	if err := os.Mkdir(validGeneration, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(validGeneration, stateFileName), []byte("db-2026.07\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(validTarget, u.InstallDir()); err != nil {
		t.Fatal(err)
	}
	if err := u.ActivateConsumer(activate); err != nil {
		t.Fatalf("valid managed pointer: %v", err)
	}
	if activations != 2 {
		t.Fatalf("activation callback ran %d times, want 2", activations)
	}
}

func TestCanonicalInstallDirResolvesExistingAliasWithoutCreatingMissingParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	aliasParent := filepath.Join(root, "alias")
	if err := os.Mkdir(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Skipf("symlink aliases unavailable: %v", err)
	}
	got, err := canonicalInstallDir(filepath.Join(aliasParent, "missing", "current"))
	if err != nil {
		t.Fatal(err)
	}
	canonicalReal, err := filepath.EvalSymlinks(realParent)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canonicalReal, "missing", "current")
	if got != want {
		t.Fatalf("canonical path = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(realParent, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path canonicalization mutated the filesystem: %v", err)
	}
}

func TestUpdater_ConcurrentChecksInstallOnce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const repo = "owner/repo"
	srv := newReleaseServer(t, repo, "db-2026.08", map[string]string{"oui.csv": "new\n"}, priv)
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	aliasParent := filepath.Join(root, "alias")
	if err := os.Mkdir(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Skipf("symlink aliases unavailable: %v", err)
	}
	dirs := []string{filepath.Join(realParent, "current"), filepath.Join(aliasParent, "current")}
	updaters := make([]*Updater, 2)
	for i := range updaters {
		var err error
		updaters[i], err = New(Config{Enabled: true, Repo: repo, APIBaseURL: srv.URL,
			InstallDir: dirs[i], PublicKey: pub})
		if err != nil {
			t.Fatal(err)
		}
	}
	if updaters[0].InstallDir() != updaters[1].InstallDir() {
		t.Fatalf("symlinked parents produced distinct lock paths: %q != %q",
			updaters[0].InstallDir(), updaters[1].InstallDir())
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, u := range updaters {
		go func(u *Updater) {
			<-start
			errs <- u.Update(context.Background())
		}(u)
	}
	close(start)
	var installed, current int
	for i := 0; i < 2; i++ {
		err := <-errs
		switch {
		case err == nil:
			installed++
		case errors.Is(err, errUpToDate):
			current++
		default:
			t.Fatalf("concurrent update: %v", err)
		}
	}
	if installed != 1 || current != 1 || srv.count("oui.csv") != 1 {
		t.Fatalf("installed=%d up_to_date=%d data_downloads=%d", installed, current, srv.count("oui.csv"))
	}
}

func TestNew_FailsClosedWithInvalidTrustRoot(t *testing.T) {
	if _, err := New(Config{InstallDir: t.TempDir(), PublicKey: ed25519.PublicKey{}}); !errors.Is(err, ErrTrustKey) {
		t.Errorf("invalid trust root: got %v, want ErrTrustKey", err)
	}
}
