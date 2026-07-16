package dbupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultRepo is the official source of signed device-DB releases.
	DefaultRepo = "MahdiHedhli/vedetta"
	// DefaultAPIBaseURL is the GitHub REST API root.
	DefaultAPIBaseURL = "https://api.github.com"
	// DefaultInterval is how often an enabled updater re-checks for a new release.
	DefaultInterval = 24 * time.Hour

	manifestAssetName  = "manifest.json"
	signatureAssetName = "manifest.json.sig"
	stateFileName      = ".db-release" // records the installed release tag
	maxMetadataBytes   = 64 << 10      // manifest.json / .sig are tiny
	defaultHTTPTimeout = 30 * time.Second
)

// ErrDisabled is returned by Update when the updater is not enabled (the default).
var ErrDisabled = errors.New("dbupdate: updater is disabled")

// Config configures the opt-in device-DB updater.
type Config struct {
	// Enabled gates all network activity. It defaults to false — the updater is opt-in
	// and never reaches the network unless an operator turns it on.
	Enabled bool
	// Repo is the "owner/repo" whose published releases are pulled. Defaults to DefaultRepo.
	Repo string
	// APIBaseURL is the GitHub API root. Defaults to DefaultAPIBaseURL; overridden in tests.
	APIBaseURL string
	// Interval is the re-check cadence when enabled. Defaults to DefaultInterval.
	Interval time.Duration
	// InstallDir is the directory verified bundle files are written into (preserving their
	// manifest-relative names). Point VEDETTA_OUI_DB_PATH at "<InstallDir>/oui.csv".
	InstallDir string
	// PublicKey is the trust root. Defaults to the compiled-in TrustedKey(); an unset or
	// invalid key makes New fail so a build without a trust root never pulls.
	PublicKey ed25519.PublicKey
	// AllowedHosts optionally restricts asset download hosts. When empty a safe default is
	// derived from APIBaseURL (api.github.com -> github.com + githubusercontent.com).
	AllowedHosts []string
	// HTTPClient overrides the default bounded client (used in tests).
	HTTPClient *http.Client
	// Logger receives progress lines. Defaults to the standard logger.
	Logger *log.Logger
}

// Updater pulls, verifies, and installs signed device-DB bundles.
type Updater struct {
	cfg          Config
	client       *http.Client
	allowedHosts map[string]struct{}
	log          *log.Logger
}

// New validates cfg and returns an Updater. It fails if there is no usable trust root, so a
// build that cannot verify signatures can never be constructed into a working updater.
func New(cfg Config) (*Updater, error) {
	if cfg.Repo == "" {
		cfg.Repo = DefaultRepo
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = DefaultAPIBaseURL
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.InstallDir == "" {
		return nil, errors.New("dbupdate: InstallDir is required")
	}
	if cfg.PublicKey == nil {
		key, err := TrustedKey()
		if err != nil {
			return nil, fmt.Errorf("dbupdate: no trust root: %w", err)
		}
		cfg.PublicKey = key
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrTrustKey
	}
	base, err := url.Parse(cfg.APIBaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("dbupdate: invalid APIBaseURL %q", cfg.APIBaseURL)
	}
	// Production must be https; http is tolerated only for a loopback test server.
	if base.Scheme != "https" && !isLoopback(base.Hostname()) {
		return nil, fmt.Errorf("dbupdate: APIBaseURL must be https, got %q", base.Scheme)
	}
	hosts := cfg.AllowedHosts
	if len(hosts) == 0 {
		hosts = defaultAllowedHosts(base)
	}
	allowed := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = struct{}{}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// Constrain redirects to the allowed hosts so a hostile API response cannot redirect the
	// fetch at an internal address (defense in depth; the signature is the ultimate gate).
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("dbupdate: too many redirects")
		}
		if _, ok := allowed[strings.ToLower(req.URL.Hostname())]; !ok {
			return fmt.Errorf("dbupdate: redirect to disallowed host %q", req.URL.Hostname())
		}
		return nil
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Updater{cfg: cfg, client: client, allowedHosts: allowed, log: logger}, nil
}

// isLoopback reports whether host is a loopback name, used only to permit an http test
// server; production endpoints must be https.
func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// defaultAllowedHosts returns the asset hosts trusted for a given API base. GitHub serves
// release assets from github.com with a redirect to objects.githubusercontent.com.
func defaultAllowedHosts(base *url.URL) []string {
	if strings.EqualFold(base.Hostname(), "api.github.com") {
		return []string{"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
	}
	return []string{strings.ToLower(base.Hostname())} // test/self-hosted: assets share the API host
}

// release is the subset of the GitHub releases API we consume.
type release struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Run performs an initial check (when enabled) and then re-checks every Interval until ctx
// is cancelled. It is a no-op that returns immediately when the updater is disabled.
func (u *Updater) Run(ctx context.Context) {
	if !u.cfg.Enabled {
		u.log.Printf("[dbupdate] disabled; using the embedded/override device DB as-is")
		return
	}
	if err := u.Update(ctx); err != nil && !errors.Is(err, errUpToDate) {
		u.log.Printf("[dbupdate] initial update failed: %v", err)
	}
	ticker := time.NewTicker(u.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.Update(ctx); err != nil && !errors.Is(err, errUpToDate) {
				u.log.Printf("[dbupdate] update failed: %v", err)
			}
		}
	}
}

var errUpToDate = errors.New("dbupdate: already at the latest release")

// Update runs one check: discover the latest published release, and if it is newer than the
// installed one, download it, verify the whole bundle, and install it atomically. It never
// touches the installed files unless a fully-verified newer bundle is ready, so a failed or
// unverifiable update leaves the last-good DB in place.
func (u *Updater) Update(ctx context.Context) error {
	if !u.cfg.Enabled {
		return ErrDisabled
	}
	rel, err := u.latestRelease(ctx)
	if err != nil {
		return err
	}
	if rel.TagName == "" {
		return errors.New("dbupdate: release has no tag")
	}
	if installed, _ := u.installedTag(); installed == rel.TagName {
		return errUpToDate
	}

	tmp, err := os.MkdirTemp("", "vedetta-dbupdate-*")
	if err != nil {
		return fmt.Errorf("dbupdate: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	manifestBytes, err := u.fetchAsset(ctx, rel, manifestAssetName, maxMetadataBytes)
	if err != nil {
		return err
	}
	sig, err := u.fetchAsset(ctx, rel, signatureAssetName, maxMetadataBytes)
	if err != nil {
		return err
	}
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return err
	}
	// Download every file the manifest lists into the staging dir before verifying.
	for _, f := range manifest.Files {
		limit := f.Bytes
		if limit < 0 || limit > maxBundleFileBytes {
			limit = maxBundleFileBytes
		}
		data, err := u.fetchAsset(ctx, rel, f.Name, limit+1)
		if err != nil {
			return err
		}
		if err := writeStaged(tmp, f.Name, data); err != nil {
			return err
		}
	}
	// Verify the whole bundle (signature + every file's size/hash) before touching anything.
	if err := VerifyBundle(os.DirFS(tmp), manifest, sig, u.cfg.PublicKey); err != nil {
		return fmt.Errorf("dbupdate: verification failed, keeping last-good: %w", err)
	}
	if err := u.install(manifest, tmp); err != nil {
		return err
	}
	if err := u.recordTag(rel.TagName); err != nil {
		u.log.Printf("[dbupdate] installed %s but could not record the tag: %v", rel.TagName, err)
	}
	u.log.Printf("[dbupdate] installed device-DB release %s (%d files)", rel.TagName, len(manifest.Files))
	return nil
}

// latestRelease fetches the newest published (non-draft, non-prerelease) release metadata.
func (u *Updater) latestRelease(ctx context.Context) (*release, error) {
	endpoint := strings.TrimRight(u.cfg.APIBaseURL, "/") + "/repos/" + u.cfg.Repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dbupdate: fetch latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dbupdate: latest release returned HTTP %d", resp.StatusCode)
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetadataBytes)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("dbupdate: decode release: %w", err)
	}
	return &rel, nil
}

// fetchAsset downloads the named release asset, enforcing the host allowlist and a size
// bound. It returns an error if the asset is absent from the release.
func (u *Updater) fetchAsset(ctx context.Context, rel *release, name string, limit int64) ([]byte, error) {
	var a *asset
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			a = &rel.Assets[i]
			break
		}
	}
	if a == nil {
		return nil, fmt.Errorf("dbupdate: release %s is missing asset %q", rel.TagName, name)
	}
	dl, err := url.Parse(a.URL)
	if err != nil || dl.Host == "" || (dl.Scheme != "https" && !isLoopback(dl.Hostname())) {
		return nil, fmt.Errorf("dbupdate: asset %q has an unsafe URL", name)
	}
	if _, ok := u.allowedHosts[strings.ToLower(dl.Hostname())]; !ok {
		return nil, fmt.Errorf("dbupdate: asset %q host %q is not allowed", name, dl.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dbupdate: download %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dbupdate: asset %q returned HTTP %d", name, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("dbupdate: read %q: %w", name, err)
	}
	return data, nil
}

// writeStaged writes a downloaded file into the staging dir under its manifest-relative
// name. isSafeName (enforced by ParseManifest) guarantees name cannot escape the dir.
func writeStaged(dir, name string, data []byte) error {
	dest := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

// install copies each verified file from the staging dir into InstallDir atomically
// (temp-in-dir + rename). It runs only after VerifyBundle has passed.
func (u *Updater) install(m *Manifest, stagingDir string) error {
	if err := os.MkdirAll(u.cfg.InstallDir, 0o755); err != nil {
		return err
	}
	for _, f := range m.Files {
		src := filepath.Join(stagingDir, filepath.FromSlash(f.Name))
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("dbupdate: reread staged %s: %w", f.Name, err)
		}
		dest := filepath.Join(u.cfg.InstallDir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := atomicWrite(dest, data); err != nil {
			return fmt.Errorf("dbupdate: install %s: %w", f.Name, err)
		}
	}
	return nil
}

// atomicWrite writes data to a temp file in the destination directory and renames it over
// path, so a reader never observes a partially-written file.
func atomicWrite(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// installedTag reads the recorded installed release tag, if any.
func (u *Updater) installedTag() (string, error) {
	data, err := os.ReadFile(filepath.Join(u.cfg.InstallDir, stateFileName))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// recordTag persists the installed release tag so a restart does not re-download it.
func (u *Updater) recordTag(tag string) error {
	if err := os.MkdirAll(u.cfg.InstallDir, 0o755); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(u.cfg.InstallDir, stateFileName), []byte(tag+"\n"))
}
