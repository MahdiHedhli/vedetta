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
	"regexp"
	"strings"
	"sync"
	"time"
)

// repoRE matches the allowed characters in an "owner/repo" GitHub slug. validRepoSlug
// additionally rejects dot path components before the value is interpolated into an API URL.
var repoRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

var installDirLocks sync.Map // map[canonical-parent-plus-managed-pointer]*sync.Mutex

const (
	// DefaultRepo is the official source of signed device-DB releases.
	DefaultRepo = "MahdiHedhli/vedetta"
	// DefaultAPIBaseURL is the GitHub REST API root.
	DefaultAPIBaseURL = "https://api.github.com"
	// DefaultInterval is how often an enabled updater re-checks for a new release.
	DefaultInterval = 24 * time.Hour

	stateFileName       = ".db-release" // records the installed release tag
	maxMetadataBytes    = 64 << 10      // manifest.json / .sig are tiny
	maxReleaseListBytes = 2 << 20       // one GitHub releases page, bounded
	defaultHTTPTimeout  = 30 * time.Second
)

// ErrDisabled is returned by Update when the updater is not enabled (the default).
var ErrDisabled = errors.New("dbupdate: updater is disabled")

// ErrDowngrade is returned when the newest available signed DB release is older than the
// installed generation. The updater never rolls a device database backward automatically.
var ErrDowngrade = errors.New("dbupdate: refusing device-DB downgrade")

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
	// InstallDir is the stable path through which verified bundle files are read. The updater
	// owns this path and atomically switches it between immutable release directories. Point
	// VEDETTA_DB_UPDATE_INSTALL_DIR at this path; consumers read "<InstallDir>/oui.csv"
	// only while signed updates are enabled.
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
	// OnInstalled runs after the generation pointer switches. It lets in-process consumers
	// reload the new files. Returning an error rolls the pointer back to the prior generation.
	OnInstalled func() error
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
	if !validRepoSlug(cfg.Repo) {
		return nil, fmt.Errorf("dbupdate: invalid Repo %q, want owner/repo", cfg.Repo)
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
	installDir, err := canonicalInstallDir(cfg.InstallDir)
	if err != nil {
		return nil, fmt.Errorf("dbupdate: resolve InstallDir: %w", err)
	}
	cfg.InstallDir = installDir
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
	// PublicKey is a slice. Keep an immutable copy so a caller cannot mutate the trust
	// root after New has validated it.
	cfg.PublicKey = append(ed25519.PublicKey(nil), cfg.PublicKey...)
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
	client := &http.Client{Timeout: defaultHTTPTimeout}
	if cfg.HTTPClient != nil {
		// Do not mutate the caller's shared client when installing our redirect policy.
		copy := *cfg.HTTPClient
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = defaultHTTPTimeout
		}
	}
	// Constrain redirects to the allowed hosts so a hostile API response cannot redirect the
	// fetch at an internal address (defense in depth; the signature is the ultimate gate).
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("dbupdate: too many redirects")
		}
		if req.URL.Scheme != "https" && !isLoopback(req.URL.Hostname()) {
			return fmt.Errorf("dbupdate: redirect to non-https host %q", req.URL.Hostname())
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

// InstallDir returns the canonical managed generation pointer validated by New. Consumers
// should use this value rather than re-resolving the caller's possibly symlinked input path.
func (u *Updater) InstallDir() string {
	return u.cfg.InstallDir
}

func validRepoSlug(repo string) bool {
	if !repoRE.MatchString(repo) {
		return false
	}
	owner, name, ok := strings.Cut(repo, "/")
	return ok && owner != "." && owner != ".." && name != "." && name != ".."
}

// canonicalInstallDir resolves symlinks in the pointer's parent without resolving the
// managed pointer itself. This makes lexical aliases share one process lock while preserving
// InstallDir as the atomic symlink that installGeneration owns. Missing parent suffixes are
// appended to the deepest existing canonical ancestor and may be created during install.
func canonicalInstallDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	parent := filepath.Dir(abs)
	existing := parent
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(existing)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Join(resolved, filepath.Base(abs)), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		next := filepath.Dir(existing)
		if next == existing {
			return "", err
		}
		missing = append(missing, filepath.Base(existing))
		existing = next
	}
}

func installDirLock(path string) *sync.Mutex {
	lock, _ := installDirLocks.LoadOrStore(path, &sync.Mutex{})
	return lock.(*sync.Mutex)
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
	TagName    string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
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
	// Different Updater instances may target the same generation pointer. Serialize the
	// complete discovery/check/download/install flow by normalized InstallDir so two
	// instances cannot race an older release over a newer one.
	lock := installDirLock(u.cfg.InstallDir)
	lock.Lock()
	defer lock.Unlock()

	rel, err := u.latestRelease(ctx)
	if err != nil {
		return err
	}
	available, ok := parseDBReleaseVersion(rel.TagName)
	if !ok {
		return fmt.Errorf("dbupdate: selected release has invalid tag %q", rel.TagName)
	}
	if err := u.requireNewerThanInstalled(available, rel.TagName); err != nil {
		return err
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
	// Authenticate the manifest BEFORE downloading the files it lists. The manifest + sig
	// are tiny and already fetched, so this cheap check stops an unsigned/forged manifest
	// from driving the client to download an attacker-declared volume of data (a DoS an
	// attacker could mount without the signing key). The per-file contents are still
	// re-verified by VerifyBundle after download.
	if err := VerifyManifest(manifest, sig, u.cfg.PublicKey); err != nil {
		return fmt.Errorf("dbupdate: manifest signature invalid, not downloading: %w", err)
	}
	// The authenticated manifest must describe the exact release selected from GitHub.
	// Otherwise an actor able to edit release assets could replay a valid older bundle under
	// a newer tag and bypass the monotonic version check.
	if manifest.Release != rel.TagName {
		return fmt.Errorf("dbupdate: signed manifest release %q does not match GitHub tag %q", manifest.Release, rel.TagName)
	}
	// Download every file the manifest lists into the staging dir before verifying contents.
	for _, f := range manifest.Files {
		limit := f.Bytes
		if limit < 0 || limit > MaxBundleFileBytes {
			limit = MaxBundleFileBytes
		}
		data, err := u.fetchAsset(ctx, rel, f.Name, limit)
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
	// Re-read the signed installed tag immediately before the pointer switch. The
	// process-wide lock prevents another Updater instance from changing it, while this
	// second check also fails closed if an external actor changed the managed generation
	// during the network/download phase.
	if err := u.requireNewerThanInstalled(available, rel.TagName); err != nil {
		return err
	}
	if err := u.installGeneration(manifest, tmp); err != nil {
		return err
	}
	u.log.Printf("[dbupdate] installed device-DB release %s (%d files)", rel.TagName, len(manifest.Files))
	return nil
}

func (u *Updater) requireNewerThanInstalled(available dbReleaseVersion, availableTag string) error {
	installed, err := u.installedTag()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dbupdate: read installed release: %w", err)
	}
	installedVersion, ok := parseDBReleaseVersion(installed)
	if !ok {
		return fmt.Errorf("dbupdate: installed release tag %q is invalid", installed)
	}
	switch compareDBReleaseVersion(available, installedVersion) {
	case 0:
		return errUpToDate
	case -1:
		return fmt.Errorf("%w: installed %s, available %s", ErrDowngrade, installed, availableTag)
	default:
		return nil
	}
}

// latestRelease finds the highest monotonically-versioned published device-DB release.
// It deliberately ignores ordinary Vedetta software releases: GitHub's /releases/latest
// endpoint is repository-wide and a newer software tag would otherwise mask DB updates.
func (u *Updater) latestRelease(ctx context.Context) (*release, error) {
	const perPage = 100
	var best *release
	var bestVersion dbReleaseVersion
	for page := 1; page <= 10; page++ {
		endpoint := fmt.Sprintf("%s/repos/%s/releases?per_page=%d&page=%d",
			strings.TrimRight(u.cfg.APIBaseURL, "/"), u.cfg.Repo, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := u.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("dbupdate: fetch releases: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("dbupdate: releases returned HTTP %d", resp.StatusCode)
		}
		limited := io.LimitReader(resp.Body, maxReleaseListBytes+1)
		body, readErr := io.ReadAll(limited)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("dbupdate: read releases: %w", readErr)
		}
		if len(body) > maxReleaseListBytes {
			return nil, errors.New("dbupdate: releases response exceeds size limit")
		}
		var releases []release
		dec := json.NewDecoder(strings.NewReader(string(body)))
		if err := dec.Decode(&releases); err != nil {
			return nil, fmt.Errorf("dbupdate: decode releases: %w", err)
		}
		for i := range releases {
			rel := &releases[i]
			version, ok := parseDBReleaseVersion(rel.TagName)
			if rel.Draft || rel.Prerelease || !ok {
				continue
			}
			if best == nil || compareDBReleaseVersion(version, bestVersion) > 0 {
				copy := *rel
				best, bestVersion = &copy, version
			}
		}
		if len(releases) < perPage {
			break
		}
	}
	if best == nil {
		return nil, errors.New("dbupdate: no published device-DB release found")
	}
	return best, nil
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
	if limit < 0 || a.Size < 0 || a.Size > limit {
		return nil, fmt.Errorf("dbupdate: asset %q exceeds size limit", name)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("dbupdate: read %q: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("dbupdate: asset %q exceeds size limit", name)
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

// installGeneration copies the complete verified bundle into a new immutable release
// directory, records its signed tag there, then atomically switches InstallDir (a managed
// symlink) to the new directory. Readers therefore observe either the complete old bundle
// or the complete new one; stale files from an older manifest disappear at the same switch.
func (u *Updater) installGeneration(m *Manifest, stagingDir string) error {
	parent := filepath.Dir(u.cfg.InstallDir)
	base := filepath.Base(u.cfg.InstallDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("dbupdate: create install parent: %w", err)
	}

	oldTarget, oldExists, err := managedLinkTarget(u.cfg.InstallDir, base)
	if err != nil {
		return err
	}
	generation, err := os.MkdirTemp(parent, "."+base+"-release-"+m.Release+"-")
	if err != nil {
		return fmt.Errorf("dbupdate: create release generation: %w", err)
	}
	keepGeneration := false
	defer func() {
		if !keepGeneration {
			_ = os.RemoveAll(generation)
		}
	}()

	for _, f := range m.Files {
		src := filepath.Join(stagingDir, filepath.FromSlash(f.Name))
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("dbupdate: reread staged %s: %w", f.Name, err)
		}
		// Re-verify the exact bytes copied into the immutable generation, closing the gap
		// between whole-bundle verification and installation.
		if err := m.verifyBytes(f.Name, data); err != nil {
			return fmt.Errorf("dbupdate: staged file changed before install: %w", err)
		}
		if err := writeGenerationFile(generation, f.Name, data); err != nil {
			return fmt.Errorf("dbupdate: install %s: %w", f.Name, err)
		}
	}
	if err := writeGenerationFile(generation, stateFileName, []byte(m.Release+"\n")); err != nil {
		return fmt.Errorf("dbupdate: record release: %w", err)
	}

	newTarget := filepath.Base(generation)
	if err := replaceLink(u.cfg.InstallDir, newTarget); err != nil {
		return fmt.Errorf("dbupdate: switch release generation: %w", err)
	}
	keepGeneration = true
	if u.cfg.OnInstalled != nil {
		if err := u.cfg.OnInstalled(); err != nil {
			// Keep runtime and disk state aligned: restore the exact prior generation when
			// the in-process consumer cannot load the new one.
			if oldExists {
				if rollbackErr := replaceLink(u.cfg.InstallDir, oldTarget); rollbackErr != nil {
					return fmt.Errorf("dbupdate: reload failed (%v) and rollback failed: %w", err, rollbackErr)
				}
			} else if removeErr := os.Remove(u.cfg.InstallDir); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return fmt.Errorf("dbupdate: reload failed (%v) and rollback failed: %w", err, removeErr)
			}
			keepGeneration = false
			return fmt.Errorf("dbupdate: consumer rejected new generation; rolled back: %w", err)
		}
	}

	if oldExists && oldTarget != newTarget {
		_ = os.RemoveAll(filepath.Join(parent, oldTarget))
	}
	return nil
}

func writeGenerationFile(root, name string, data []byte) error {
	dest := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// managedLinkTarget validates that InstallDir is either absent or one of our generation
// symlinks. Refusing a real directory prevents an opt-in update from replacing operator
// data that it does not own.
func managedLinkTarget(path, base string) (target string, exists bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("dbupdate: inspect install path: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false, fmt.Errorf("dbupdate: install path %s exists and is not a managed symlink", path)
	}
	target, err = os.Readlink(path)
	if err != nil {
		return "", false, fmt.Errorf("dbupdate: read install pointer: %w", err)
	}
	if filepath.IsAbs(target) || filepath.Base(target) != target || !strings.HasPrefix(target, "."+base+"-release-db-") {
		return "", false, fmt.Errorf("dbupdate: install path %s is not a managed release pointer", path)
	}
	return target, true, nil
}

func replaceLink(path, target string) error {
	parent := filepath.Dir(path)
	tmp, err := os.CreateTemp(parent, ".db-link-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	defer os.Remove(tmpName)
	if err := os.Symlink(target, tmpName); err != nil {
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
