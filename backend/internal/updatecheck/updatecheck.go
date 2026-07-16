// Package updatecheck reports whether a newer Vedetta software release (a v* tag) or signed
// device-DB release (a db-* tag) is available, by periodically listing the repository's
// public GitHub releases. It is strictly read-only — it never downloads, verifies, or
// installs anything — so it is safe to run on by default: a release check reveals only that
// a Vedetta instance exists (the same exposure as the community feed) and is disableable.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
	maxReleaseBytes   = 1 << 20 // one releases page, bounded
	maxReleasesPage   = 100
	httpTimeout       = 20 * time.Second
)

var (
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	semverRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)`)
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
	// CurrentVersion is the running build version (e.g. "v1.2.3" or "dev"). A non-semver
	// value (like a dev build) suppresses the software-update signal.
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
	if !repoRE.MatchString(cfg.Repo) {
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
	client := cfg.HTTPClient
	if client == nil {
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
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// Refresh performs one poll and updates the cached Status.
func (c *Checker) Refresh(ctx context.Context) error {
	releases, err := c.listReleases(ctx)
	if err != nil {
		return err
	}

	status := Status{Enabled: true, CheckedAt: c.cfg.Now().UTC().Format(time.RFC3339)}

	if rel := firstMatch(releases, softwareTagPrefix, isSemverTag); rel != nil {
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
	if rel := firstMatch(releases, deviceDBTagPrefix, nil); rel != nil {
		status.DeviceDB = Component{
			Current:         installedDB,
			Latest:          rel.TagName,
			UpdateAvailable: rel.TagName != installedDB,
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

// listReleases fetches the newest page of published releases (newest first).
func (c *Checker) listReleases(ctx context.Context) ([]ghRelease, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/releases?per_page=%d",
		strings.TrimRight(c.cfg.APIBaseURL, "/"), c.cfg.Repo, maxReleasesPage)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("updatecheck: list releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("updatecheck: releases returned HTTP %d", resp.StatusCode)
	}
	var releases []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReleaseBytes)).Decode(&releases); err != nil {
		return nil, fmt.Errorf("updatecheck: decode releases: %w", err)
	}
	return releases, nil
}

// firstMatch returns the first published (non-draft, non-prerelease) release whose tag has
// the given prefix and, optionally, satisfies extra. The API lists releases newest-first, so
// the first match is the latest.
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

// safeReleaseURL returns raw only if it is an https URL on the same host family as the API
// (so a hostile API response cannot inject a javascript:/http: link into the dashboard).
func (c *Checker) safeReleaseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "github.com" || host == c.apiHost || strings.TrimPrefix(c.apiHost, "api.") == host {
		return raw
	}
	return ""
}

func isSemverTag(tag string) bool { return semverRE.MatchString(tag) }

// isNewerSemver reports whether latest is a strictly higher vMAJOR.MINOR.PATCH than current.
// A non-semver current (e.g. "dev") yields false so a local build is never nagged.
func isNewerSemver(latest, current string) bool {
	lm := semverRE.FindStringSubmatch(latest)
	cm := semverRE.FindStringSubmatch(current)
	if lm == nil || cm == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		l, _ := strconv.Atoi(lm[i])
		cur, _ := strconv.Atoi(cm[i])
		if l != cur {
			return l > cur
		}
	}
	return false
}

func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
