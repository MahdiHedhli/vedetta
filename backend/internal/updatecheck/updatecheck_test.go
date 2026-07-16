package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serveReleases(t *testing.T, repo string, releases []ghRelease) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+repo+"/releases", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
		}
		if got := r.URL.Query().Get("per_page"); got != strconv.Itoa(maxReleasesPage) {
			t.Errorf("per_page = %q, want %d", got, maxReleasesPage)
		}
		_ = json.NewEncoder(w).Encode(releases)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRefresh_SoftwareAndDeviceDB(t *testing.T) {
	const repo = "owner/repo"
	// Newest-first, with a prerelease and a draft that must be ignored.
	releases := []ghRelease{
		{TagName: "db-2026.07", HTMLURL: "https://github.com/owner/repo/releases/tag/db-2026.07"},
		{TagName: "v1.4.0", HTMLURL: "https://github.com/owner/repo/releases/tag/v1.4.0", Prerelease: true},
		{TagName: "v1.3.0", HTMLURL: "https://github.com/owner/repo/releases/tag/v1.3.0"},
		{TagName: "db-2026.08", Draft: true},
		{TagName: "v1.2.0", HTMLURL: "https://github.com/owner/repo/releases/tag/v1.2.0"},
	}
	srv := serveReleases(t, repo, releases)
	c, err := New(Config{
		Enabled: true, Repo: repo, APIBaseURL: srv.URL, CurrentVersion: "v1.2.0",
		InstalledDBTag: func() string { return "db-2026.06" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.Status()

	if s.Software.Latest != "v1.3.0" || !s.Software.UpdateAvailable {
		t.Errorf("software = %+v, want latest v1.3.0 + update available (prerelease v1.4.0 ignored)", s.Software)
	}
	if s.Software.URL == "" {
		t.Error("expected a sanitized software release URL")
	}
	if s.DeviceDB.Latest != "db-2026.07" || !s.DeviceDB.UpdateAvailable {
		t.Errorf("device_db = %+v, want latest db-2026.07 + update available", s.DeviceDB)
	}
	if !s.Enabled || s.CheckedAt == "" {
		t.Errorf("status envelope = %+v, want enabled + checked_at set", s)
	}
}

func TestRefresh_NoUpdateWhenCurrentIsLatest(t *testing.T) {
	releases := []ghRelease{
		{TagName: "v1.2.0", HTMLURL: "https://github.com/o/r/releases/tag/v1.2.0"},
		{TagName: "db-2026.07", HTMLURL: "https://github.com/o/r/releases/tag/db-2026.07"},
	}
	srv := serveReleases(t, "o/r", releases)
	c, _ := New(Config{
		Enabled: true, Repo: "o/r", APIBaseURL: srv.URL, CurrentVersion: "v1.2.0",
		InstalledDBTag: func() string { return "db-2026.07" },
	})
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.Status()
	if s.Software.UpdateAvailable {
		t.Error("no software update expected when current == latest")
	}
	if s.DeviceDB.UpdateAvailable {
		t.Error("no device-DB update expected when installed == latest")
	}
}

func TestRefresh_DeviceDBAvailableWhenNoneInstalled(t *testing.T) {
	releases := []ghRelease{{TagName: "db-2026.07", HTMLURL: "https://github.com/o/r/releases/tag/db-2026.07"}}
	srv := serveReleases(t, "o/r", releases)
	c, _ := New(Config{Enabled: true, Repo: "o/r", APIBaseURL: srv.URL, CurrentVersion: "dev"}) // no InstalledDBTag
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Status().DeviceDB.UpdateAvailable {
		t.Error("a published db release should read as available when nothing is installed")
	}
}

func TestRefresh_DeviceDBDoesNotAdvertiseDowngradeOrInvalidTag(t *testing.T) {
	releases := []ghRelease{
		{ID: 3, TagName: "db-not-a-version", PublishedAt: time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)},
		{ID: 2, TagName: "db-2026.07", PublishedAt: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)},
	}
	srv := serveReleases(t, "o/r", releases)
	c, err := New(Config{
		Enabled: true, Repo: "o/r", APIBaseURL: srv.URL, CurrentVersion: "dev",
		InstalledDBTag: func() string { return "db-2026.08" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.Status().DeviceDB; got.Latest != "db-2026.07" || got.UpdateAvailable {
		t.Fatalf("device DB = %+v, want valid older tag without update notice", got)
	}
}

func TestRefresh_BetaBuildSeesNewerPrerelease(t *testing.T) {
	releases := []ghRelease{
		{ID: 4, TagName: "v0.1.0-beta.4", Prerelease: true, PublishedAt: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)},
		{ID: 3, TagName: "v0.1.0-beta.3", Prerelease: true, PublishedAt: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
	}
	srv := serveReleases(t, "o/r", releases)
	c, err := New(Config{Enabled: true, Repo: "o/r", APIBaseURL: srv.URL, CurrentVersion: "v0.1.0-beta.3"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.Status().Software; got.Latest != "v0.1.0-beta.4" || !got.UpdateAvailable {
		t.Fatalf("software = %+v, want beta.4 update", got)
	}
}

func TestRefresh_SortsByPublishedAt(t *testing.T) {
	const repo = "owner/repo"
	releases := []ghRelease{
		{ID: 1, TagName: "v1.1.0", PublishedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
		{ID: 2, TagName: "db-2026.07", PublishedAt: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)},
		{ID: 4, TagName: "db-2026.08", PublishedAt: time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)},
		{ID: 3, TagName: "v1.2.0", PublishedAt: time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)},
	}
	srv := serveReleases(t, repo, releases)
	c, err := New(Config{
		Enabled: true, Repo: repo, APIBaseURL: srv.URL, CurrentVersion: "v1.0.0",
		InstalledDBTag: func() string { return "db-2026.06" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := c.Status()
	if status.Software.Latest != "v1.2.0" || status.DeviceDB.Latest != "db-2026.08" {
		t.Fatalf("status = %+v, want newest publication in each channel", status)
	}
}

func TestRefresh_PaginatesAcrossReleaseChannels(t *testing.T) {
	const repo = "owner/repo"
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+repo+"/releases", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.URL.Query().Get("per_page"); got != strconv.Itoa(maxReleasesPage) {
			t.Errorf("per_page = %q, want %d", got, maxReleasesPage)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			decoys := make([]ghRelease, maxReleasesPage)
			for i := range decoys {
				decoys[i] = ghRelease{ID: int64(i + 1), TagName: fmt.Sprintf("notes-%02d", i)}
			}
			_ = json.NewEncoder(w).Encode(decoys)
		case "2":
			_ = json.NewEncoder(w).Encode([]ghRelease{
				{ID: 101, TagName: "v1.1.0", PublishedAt: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)},
				{ID: 102, TagName: "db-2026.08", PublishedAt: time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)},
			})
		default:
			t.Fatalf("unexpected release page %q", r.URL.Query().Get("page"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := New(Config{
		Enabled: true, Repo: repo, APIBaseURL: srv.URL, CurrentVersion: "v1.0.0",
		InstalledDBTag: func() string { return "db-2026.07" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := c.Status()
	if status.Software.Latest != "v1.1.0" || !status.Software.UpdateAvailable {
		t.Fatalf("software = %+v, want update from page 2", status.Software)
	}
	if status.DeviceDB.Latest != "db-2026.08" || !status.DeviceDB.UpdateAvailable {
		t.Fatalf("device DB = %+v, want update from page 2", status.DeviceDB)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("release API calls = %d, want 2 bounded pages", got)
	}
}

func TestListReleases_StopsAtPageLimit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 || page > maxReleasePages {
			t.Fatalf("unexpected release page %q", r.URL.Query().Get("page"))
		}
		calls.Add(1)
		items := make([]ghRelease, maxReleasesPage)
		for i := range items {
			items[i] = ghRelease{ID: int64((page-1)*maxReleasesPage + i + 1)}
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer srv.Close()
	c, err := New(Config{Enabled: true, Repo: "o/r", APIBaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	releases, err := c.listReleases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(releases), maxReleasePages*maxReleasesPage; got != want {
		t.Fatalf("releases = %d, want bounded maximum %d", got, want)
	}
	if got := calls.Load(); got != maxReleasePages {
		t.Fatalf("release API calls = %d, want page limit %d", got, maxReleasePages)
	}
}

func TestRefresh_DisabledMakesNoNetworkCall(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()
	c, err := New(Config{Enabled: false, Repo: "o/r", APIBaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Refresh error = %v, want ErrDisabled", err)
	}
	c.Run(context.Background()) // returns immediately, makes no calls
	if got := calls.Load(); got != 0 {
		t.Fatalf("disabled checker made %d network calls", got)
	}
	if c.Status().Enabled {
		t.Error("disabled checker must report Enabled=false")
	}
}

func TestRefresh_ErrorPreservesLastGoodStatus(t *testing.T) {
	const repo = "o/r"
	var fail atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "temporary failure", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode([]ghRelease{{
			ID: 1, TagName: "v1.2.0", PublishedAt: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC),
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	checkedAt := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	c, err := New(Config{
		Enabled: true, Repo: repo, APIBaseURL: srv.URL, CurrentVersion: "v1.1.0",
		Now: func() time.Time { return checkedAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := c.Status()
	fail.Store(true)
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh unexpectedly succeeded after server failure")
	}
	if got := c.Status(); got != want {
		t.Fatalf("failed refresh changed status\n got: %+v\nwant: %+v", got, want)
	}
}

func TestRefresh_RejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxReleaseBytes+1)))
	}))
	defer srv.Close()
	c, err := New(Config{Enabled: true, Repo: "o/r", APIBaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Refresh error = %v, want oversized-response error", err)
	}
}

func TestSafeReleaseURL(t *testing.T) {
	c, _ := New(Config{})
	if c.safeReleaseURL("https://github.com/o/r/releases/tag/v1") == "" {
		t.Error("github https URL should be kept")
	}
	for _, bad := range []string{"javascript:alert(1)", "http://github.com/x", "https://evil.example/x", "https://github.com:444/x", ""} {
		if c.safeReleaseURL(bad) != "" {
			t.Errorf("unsafe URL %q should be dropped", bad)
		}
	}
}

func TestIsNewerSemver(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.3.0", "v1.2.9", true},
		{"v1.2.0", "v1.2.0", false},
		{"v1.2.0", "v1.3.0", false},
		{"v2.0.0", "v1.9.9", true},
		{"v1.2.3", "dev", false},
		{"garbage", "v1.0.0", false},
		{"v1.2.4-rc.1", "v1.2.3", true},
		{"v1.2.3-rc.1", "v1.2.3-beta.4", true},
		{"v1.2.3", "v1.2.3-rc.1", true},
		{"v1.2.3-rc.1", "v1.2.3", false},
		{"v1.2.4extra", "v1.2.3", false},
		{"v1.2.4-beta.01", "v1.2.3", false},
		{"v18446744073709551616.0.0", "v1.0.0", true},
	}
	for _, tc := range cases {
		if got := isNewerSemver(tc.latest, tc.current); got != tc.want {
			t.Errorf("isNewerSemver(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestSemverPrereleaseOrdering(t *testing.T) {
	ordered := []string{
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0-alpha.beta",
		"v1.0.0-beta",
		"v1.0.0-beta.2",
		"v1.0.0-beta.11",
		"v1.0.0-rc.1",
		"v1.0.0",
	}
	for i := 1; i < len(ordered); i++ {
		if !isNewerSemver(ordered[i], ordered[i-1]) {
			t.Fatalf("expected %s > %s", ordered[i], ordered[i-1])
		}
	}
}

func TestNewRejectsDotSegmentRepoSlugs(t *testing.T) {
	for _, repo := range []string{"../repo", "owner/..", "./repo", "owner/."} {
		if _, err := New(Config{Repo: repo}); err == nil {
			t.Errorf("New accepted invalid repo slug %q", repo)
		}
	}
}

func TestNewCopiesHTTPClientAndAppliesDefaultTimeout(t *testing.T) {
	original := &http.Client{}
	c, err := New(Config{HTTPClient: original})
	if err != nil {
		t.Fatal(err)
	}
	if original.Timeout != 0 {
		t.Fatalf("New mutated caller client timeout to %v", original.Timeout)
	}
	if c.client == original || c.client.Timeout != httpTimeout {
		t.Fatalf("checker client = %#v, want independent copy with %v timeout", c.client, httpTimeout)
	}
}
