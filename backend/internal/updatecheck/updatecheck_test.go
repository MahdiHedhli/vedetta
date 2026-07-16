package updatecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveReleases(t *testing.T, repo string, releases []ghRelease) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
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

func TestDisabled_IsANoop(t *testing.T) {
	c, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	c.Run(context.Background()) // returns immediately, makes no calls
	if c.Status().Enabled {
		t.Error("disabled checker must report Enabled=false")
	}
}

func TestSafeReleaseURL(t *testing.T) {
	c, _ := New(Config{})
	if c.safeReleaseURL("https://github.com/o/r/releases/tag/v1") == "" {
		t.Error("github https URL should be kept")
	}
	for _, bad := range []string{"javascript:alert(1)", "http://github.com/x", "https://evil.example/x", ""} {
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
	}
	for _, tc := range cases {
		if got := isNewerSemver(tc.latest, tc.current); got != tc.want {
			t.Errorf("isNewerSemver(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}
