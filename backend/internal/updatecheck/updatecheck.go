// Package updatecheck reports whether a newer Vedetta software release (a v* tag) or signed
// device-DB release (a db-* tag) is available, by periodically listing the repository's
// public GitHub releases. It is strictly read-only — it never downloads, verifies, or
// installs anything — so it is safe to run on by default: a release check reveals only that
// a Vedetta instance exists (the same exposure as the community feed) and is disableable.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/dbupdate"
)

const (
	// DefaultRepo is the official source of Vedetta releases.
	DefaultRepo = "MahdiHedhli/vedetta"
	// DefaultAPIBaseURL is the GitHub REST API root.
	DefaultAPIBaseURL = "https://api.github.com"
	// DefaultInterval is how often an enabled checker re-polls for releases.
	DefaultInterval = 6 * time.Hour

	softwareTagPrefix = "v"
	deviceDBTagPrefix = "db-"
	maxReleaseBytes   = 4 << 20 // one releases page, bounded
	maxReleasesPage   = 20
	httpTimeout       = 20 * time.Second
	userAgent         = "Vedetta-UpdateChecker/1"
)

var (
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	semverRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

	// ErrDisabled is returned when a direct Refresh call attempts to bypass the
	// operator's process-level opt-out.
	ErrDisabled = errors.New("updatecheck: checker is disabled")
)

// Component describes the update state for one release channel.
type Component struct {
	Current         string `json:"current,omitempty"`
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	URL             string `json:"url,omitempty"`
}

// Status is the cached result served to the dashboard.
type Status struct {
	Enabled   bool      `json:"enabled"`
	CheckedAt string    `json:"checked_at,omitempty"`
	Software  Component `json:"software"`
	DeviceDB  Component `json:"device_db"`
}

// Config configures the read-only update checker.
type Config struct {
	// Enabled defaults to true (opt-out). When false the checker makes no network calls and
	// Status reports Enabled=false.
	Enabled bool
	// Repo is the "owner/repo" whose releases are polled. Defaults to DefaultRepo.
	Repo string
	// APIBaseURL is the GitHub API root. Defaults to DefaultAPIBaseURL; overridden in tests.
	APIBaseURL string
	// Interval is the re-poll cadence. Defaults to DefaultInterval.
	Interval time.Duration
	// CurrentVersion is the running build version (e.g. "v1.2.3", "v1.2.3-beta.4", or
	// "dev"). A non-semver value (like a dev build) suppresses the software-update signal.
	CurrentVersion string
	// InstalledDBTag returns the installed signed device-DB tag, or "" if none. Optional.
	InstalledDBTag func() string
	// HTTPClient overrides the default bounded client (tests).
	HTTPClient *http.Client
	// Logger receives progress lines. Defaults to the standard logger.
	Logger *log.Logger
	// Now returns the current time; defaults to time.Now (overridable in tests).
	Now func() time.Time
}

// Checker polls for releases and serves the cached Status.
type Checker struct {
	cfg     Config
	client  *http.Client
	apiHost string
	log     *log.Logger

	mu     sync.RWMutex
	status Status
}

// New validates cfg and returns a Checker. The zero-value Enabled (false) is respected; use
// Config{Enabled: true, ...} for the opt-out default the wiring applies.
func New(cfg Config) (*Checker, error) {
	if cfg.Repo == "" {
		cfg.Repo = DefaultRepo
	}
	if !validRepoSlug(cfg.Repo) {
		return nil, fmt.Errorf("updatecheck: invalid Repo %q", cfg.Repo)
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = DefaultAPIBaseURL
	}
	base, err := url.Parse(cfg.APIBaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && !isLoopback(base.Hostname())) {
		return nil, fmt.Errorf("updatecheck: invalid APIBaseURL %q", cfg.APIBaseURL)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var client *http.Client
	if cfg.HTTPClient != nil {
		copy := *cfg.HTTPClient
		if copy.Timeout == 0 {
			copy.Timeout = httpTimeout
		}
		client = &copy
	} else {
		client = &http.Client{Timeout: httpTimeout}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Checker{
		cfg:     cfg,
		client:  client,
		apiHost: strings.ToLower(base.Hostname()),
		log:     logger,
		status:  Status{Enabled: cfg.Enabled},
	}, nil
}

// Status returns the latest cached result.
func (c *Checker) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// Run polls immediately and then every Interval until ctx is cancelled. It is a no-op that
// returns at once when the checker is disabled.
func (c *Checker) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		c.log.Printf("[updatecheck] disabled; dashboard will not show release-update notices")
		return
	}
	if err := c.Refresh(ctx); err != nil {
		c.log.Printf("[updatecheck] initial check failed: %v", err)
	}
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil {
				c.log.Printf("[updatecheck] check failed: %v", err)
			}
		}
	}
}

// ghRelease is the subset of the GitHub releases API we consume.
type ghRelease struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	ID          int64     `json:"id"`
	PublishedAt time.Time `json:"published_at"`
}

// Refresh performs one poll and updates the cached Status.
func (c *Checker) Refresh(ctx context.Context) error {
	if !c.cfg.Enabled {
		return ErrDisabled
	}
	releases, err := c.listReleases(ctx)
	if err != nil {
		return err
	}
	// GitHub does not contractually guarantee the REST response order. Prefer the
	// latest publication and use the immutable release ID as a deterministic tie-break.
	sort.SliceStable(releases, func(i, j int) bool {
		if releases[i].PublishedAt.Equal(releases[j].PublishedAt) {
			return releases[i].ID > releases[j].ID
		}
		return releases[i].PublishedAt.After(releases[j].PublishedAt)
	})

	status := Status{Enabled: true, CheckedAt: c.cfg.Now().UTC().Format(time.RFC3339)}

	if rel := latestSoftwareMatch(releases, c.cfg.CurrentVersion); rel != nil {
		status.Software = Component{
			Current:         c.cfg.CurrentVersion,
			Latest:          rel.TagName,
			UpdateAvailable: isNewerSemver(rel.TagName, c.cfg.CurrentVersion),
			URL:             c.safeReleaseURL(rel.HTMLURL),
		}
	} else {
		status.Software = Component{Current: c.cfg.CurrentVersion}
	}

	installedDB := ""
	if c.cfg.InstalledDBTag != nil {
		installedDB = strings.TrimSpace(c.cfg.InstalledDBTag())
	}
	if rel := firstMatch(releases, deviceDBTagPrefix, isDeviceDBTag); rel != nil {
		updateAvailable := installedDB == ""
		if installedDB != "" {
			comparison, ok := dbupdate.CompareReleaseTags(rel.TagName, installedDB)
			updateAvailable = ok && comparison > 0
		}
		status.DeviceDB = Component{
			Current:         installedDB,
			Latest:          rel.TagName,
			UpdateAvailable: updateAvailable,
			URL:             c.safeReleaseURL(rel.HTMLURL),
		}
	} else {
		status.DeviceDB = Component{Current: installedDB}
	}

	c.mu.Lock()
	c.status = status
	c.mu.Unlock()
	return nil
}

func isDeviceDBTag(tag string) bool {
	_, ok := dbupdate.CompareReleaseTags(tag, tag)
	return ok
}

// listReleases fetches the newest page of published releases (newest first).
func (c *Checker) listReleases(ctx context.Context) ([]ghRelease, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/releases?per_page=%d",
		strings.TrimRight(c.cfg.APIBaseURL, "/"), c.cfg.Repo, maxReleasesPage)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("updatecheck: list releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("updatecheck: releases returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("updatecheck: read releases: %w", err)
	}
	if len(body) > maxReleaseBytes {
		return nil, fmt.Errorf("updatecheck: releases response exceeds %d bytes", maxReleaseBytes)
	}
	var releases []ghRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("updatecheck: decode releases: %w", err)
	}
	return releases, nil
}

// firstMatch returns the first published (non-draft, non-prerelease) release whose tag has
// the given prefix and, optionally, satisfies extra. Refresh sorts releases newest-first
// before calling it.
func firstMatch(releases []ghRelease, prefix string, extra func(string) bool) *ghRelease {
	for i := range releases {
		r := &releases[i]
		if r.Draft || r.Prerelease || !strings.HasPrefix(r.TagName, prefix) {
			continue
		}
		if extra != nil && !extra(r.TagName) {
			continue
		}
		return r
	}
	return nil
}

// latestSoftwareMatch returns the highest semantic software version visible to the
// running release channel. Stable builds ignore prereleases; prerelease builds receive
// both newer prereleases and the eventual stable release. Source/dev builds return nil.
func latestSoftwareMatch(releases []ghRelease, current string) *ghRelease {
	currentVersion, ok := parseSemver(current)
	if !ok {
		return nil
	}
	allowPrerelease := len(currentVersion.prerelease) > 0
	var best *ghRelease
	var bestVersion semanticVersion
	for i := range releases {
		release := &releases[i]
		if release.Draft || !strings.HasPrefix(release.TagName, softwareTagPrefix) {
			continue
		}
		version, ok := parseSemver(release.TagName)
		if !ok || (!allowPrerelease && (release.Prerelease || len(version.prerelease) > 0)) {
			continue
		}
		if best == nil || compareSemver(version, bestVersion) > 0 {
			best = release
			bestVersion = version
		}
	}
	return best
}

// safeReleaseURL returns raw only if it is an https URL on the same host family as the API
// (so a hostile API response cannot inject a javascript:/http: link into the dashboard).
func (c *Checker) safeReleaseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "github.com" || host == c.apiHost || strings.TrimPrefix(c.apiHost, "api.") == host {
		return raw
	}
	return ""
}

type semanticVersion struct {
	core       [3]string
	prerelease []string
}

func parseSemver(tag string) (semanticVersion, bool) {
	match := semverRE.FindStringSubmatch(tag)
	if match == nil {
		return semanticVersion{}, false
	}
	version := semanticVersion{core: [3]string{match[1], match[2], match[3]}}
	if match[4] != "" {
		version.prerelease = strings.Split(match[4], ".")
		for _, identifier := range version.prerelease {
			if isNumeric(identifier) && len(identifier) > 1 && identifier[0] == '0' {
				return semanticVersion{}, false
			}
		}
	}
	return version, true
}

// isNewerSemver reports whether latest is a strictly higher semantic version than current.
// A non-semver current (e.g. "dev") yields false so a local build is never nagged.
func isNewerSemver(latest, current string) bool {
	l, lok := parseSemver(latest)
	cur, cok := parseSemver(current)
	if !lok || !cok {
		return false
	}
	return compareSemver(l, cur) > 0
}

func compareSemver(a, b semanticVersion) int {
	for i := range a.core {
		if cmp := compareNumeric(a.core[i], b.core[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a.prerelease) == 0 && len(b.prerelease) == 0 {
		return 0
	}
	if len(a.prerelease) == 0 {
		return 1
	}
	if len(b.prerelease) == 0 {
		return -1
	}
	limit := len(a.prerelease)
	if len(b.prerelease) < limit {
		limit = len(b.prerelease)
	}
	for i := 0; i < limit; i++ {
		aNumeric, bNumeric := isNumeric(a.prerelease[i]), isNumeric(b.prerelease[i])
		switch {
		case aNumeric && bNumeric:
			if cmp := compareNumeric(a.prerelease[i], b.prerelease[i]); cmp != 0 {
				return cmp
			}
		case aNumeric:
			return -1
		case bNumeric:
			return 1
		case a.prerelease[i] < b.prerelease[i]:
			return -1
		case a.prerelease[i] > b.prerelease[i]:
			return 1
		}
	}
	switch {
	case len(a.prerelease) < len(b.prerelease):
		return -1
	case len(a.prerelease) > len(b.prerelease):
		return 1
	default:
		return 0
	}
}

func compareNumeric(a, b string) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validRepoSlug(repo string) bool {
	if !repoRE.MatchString(repo) {
		return false
	}
	owner, name, ok := strings.Cut(repo, "/")
	return ok && owner != "." && owner != ".." && name != "." && name != ".."
}

func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
