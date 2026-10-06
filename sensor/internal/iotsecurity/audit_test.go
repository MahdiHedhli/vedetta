package iotsecurity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeAuditFixture(t *testing.T, root, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, mode); err != nil {
		t.Fatal(err)
	}
	return filename
}

func coverageFor(t *testing.T, observation Observation, check string) Coverage {
	t.Helper()
	for _, coverage := range observation.Coverage {
		if coverage.Check == check {
			return coverage
		}
	}
	t.Fatalf("missing coverage for %s", check)
	return Coverage{}
}

func TestAuditCollectsArtifactsWithoutExecution(t *testing.T) {
	root := t.TempDir()
	data := []byte("\x7fELF synthetic fixture .selfrep\x00/.cling\x00User-Agent: clingwashere\x00mount --bind /tmp /proc/%d")
	filename := writeAuditFixture(t, root, "/root/.cling", data, 0o755)
	writeAuditFixture(t, root, "/usr/bin/wget.r", []byte("synthetic original downloader"), 0o755)
	writeAuditFixture(t, root, "/usr/bin/wget.p", []byte("/usr/bin/wget.r"), 0o644)
	writeAuditFixture(t, root, "/etc/inittab", []byte("::sysinit:/root/.cling\n"), 0o644)
	writeAuditFixture(t, root, "/etc/init.d/rcS", []byte("#!/bin/sh\n# /usr/local/bin/.cling\necho '/usr/local/bin/.cling'\nexec /root/.cling &\n"), 0o755)
	observation, err := Audit(root, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if observation.Kind != "host_audit" || observation.SubjectIP != "192.0.2.10" || len(observation.Files) != 5 {
		t.Fatalf("unexpected audit: %+v", observation)
	}
	file := observation.Files[0]
	wantDigest := sha256.Sum256(data)
	if file.SHA256 != hex.EncodeToString(wantDigest[:]) || file.Size != int64(len(data)) || file.MagicHex != "7f454c46" || !file.Executable || !reflect.DeepEqual(file.Markers, fileMarkers) {
		t.Fatalf("incorrect file facts: %+v", file)
	}
	if len(observation.Persistence) != 2 {
		t.Fatalf("expected two execution references, excluding comments/echo: %+v", observation.Persistence)
	}
	for _, persistence := range observation.Persistence {
		if persistence.Target != "/root/.cling" {
			t.Fatal("a comment or quoted echo was treated as persistence")
		}
	}
	after, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("audit changed an inspected file")
	}
	if coverageFor(t, observation, "filesystem_audit").Status != "complete" {
		t.Fatal("complete allowlist read should report complete collection")
	}
}

func TestSDKRequiresComponentAndExplicitVersionMarker(t *testing.T) {
	cases := []struct {
		name, marker, version string
		component             []byte
		want                  bool
	}{
		{"documented version", "The SDK version is: Realtek SDK v3.2.3-r14377\n", "3.2.3-r14377", []byte("\x7fELFfixture"), true},
		{"explicit jungle", "Realtek Jungle SDK: v3.4.14B", "3.4.14B", []byte("\x7fELFfixture"), true},
		{"unknown jungle version", "Realtek Jungle SDK", "", []byte("\x7fELFfixture"), true},
		{"RLX is not an SDK version", "RLX Linux version 2.0\n", "", []byte("\x7fELFfixture"), false},
		{"non-ELF named component", "Realtek SDK v3.2.3", "", []byte("UDPServer documentation"), false},
		{"unrelated family", "Realtek Luna SDK v1.3.2", "", []byte("\x7fELFfixture"), false},
		{"new unspecified family", "Realtek SDK v8.0", "", []byte("\x7fELFfixture"), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeAuditFixture(t, root, "/bin/UDPServer", tt.component, 0o755)
			writeAuditFixture(t, root, "/etc/version", []byte(tt.marker), 0o644)
			observation, err := Audit(root, "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			if (observation.SDK != nil) != tt.want {
				t.Fatalf("unexpected SDK evidence: %+v", observation.SDK)
			}
			if tt.want && (observation.SDK.Version != tt.version || observation.SDK.Family != "realtek_jungle" || observation.SDK.ComponentPath != "/bin/UDPServer" || observation.SDK.MarkerPath != "/etc/version") {
				t.Fatalf("unexpected SDK facts: %+v", observation.SDK)
			}
		})
	}
}

func TestAuditEmptyRootIsNotCleanAndSubjectOptional(t *testing.T) {
	observation, err := Audit(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if observation.SubjectIP != "" || len(observation.Files) != 0 || observation.SDK != nil {
		t.Fatalf("audit inferred facts from an empty root: %+v", observation)
	}
	coverage := coverageFor(t, observation, "filesystem_audit")
	if coverage.Status != "complete" || !strings.Contains(coverage.Detail, "does not establish a clean") {
		t.Fatalf("missing negative-result limitation: %+v", coverage)
	}
	if _, err := Audit("", "192.0.2.1"); err == nil {
		t.Fatal("implicit filesystem root accepted")
	}
	for _, subject := range []string{"not-an-ip", "0.0.0.0", "::", "224.0.0.1"} {
		if _, err := Audit(t.TempDir(), subject); err == nil {
			t.Fatalf("invalid subject accepted: %s", subject)
		}
	}
}

func TestAuditRejectsSymlinkEscapesAndInRootLinks(t *testing.T) {
	for _, parentLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "file link", true: "directory link"}[parentLink], func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			outsideFile := writeAuditFixture(t, outside, "/.cling", []byte("\x7fELFoutside-secret"), 0o755)
			var err error
			if parentLink {
				err = os.Symlink(outside, filepath.Join(root, "root"))
			} else {
				if err := os.Mkdir(filepath.Join(root, "root"), 0o755); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(outsideFile, filepath.Join(root, "root", ".cling"))
			}
			if err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			observation, err := Audit(root, "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			if len(observation.Files) != 0 || coverageFor(t, observation, "/root/.cling").Status != "skipped" || coverageFor(t, observation, "filesystem_audit").Status != "partial" {
				t.Fatalf("escaped symlink was not safely omitted: %+v", observation)
			}
		})
	}
	root := t.TempDir()
	writeAuditFixture(t, root, "/root/synthetic", []byte("safe in-root fixture"), 0o644)
	if err := os.Symlink("synthetic", filepath.Join(root, "root", ".cling")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	observation, err := Audit(root, "192.0.2.10")
	if err != nil || len(observation.Files) != 0 || coverageFor(t, observation, "/root/.cling").Status != "skipped" {
		t.Fatal("symlink policy must also report skipped in-root links")
	}
}

func TestAuditSizeAndEvidenceBounds(t *testing.T) {
	root := t.TempDir()
	for _, candidate := range auditPaths() {
		writeAuditFixture(t, root, candidate.name, []byte("synthetic bounded file"), 0o644)
	}
	observation, err := Audit(root, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Files) != 27 || len(observation.Files) > 32 || len(observation.Coverage) > 64 || len(observation.Persistence) > 16 {
		t.Fatalf("unexpected audit evidence bounds: %+v", observation)
	}
	file, err := os.OpenFile(filepath.Join(root, "root", ".cling"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxAuditBinarySize + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	writeAuditFixture(t, root, "/etc/version", bytes.Repeat([]byte{'x'}, maxAuditTextSize+1), 0o644)
	observation, err = Audit(root, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/root/.cling", "/etc/version"} {
		if coverageFor(t, observation, name).Status != "skipped" {
			t.Fatalf("oversized path not skipped: %s", name)
		}
		for _, evidence := range observation.Files {
			if evidence.Path == name {
				t.Fatalf("oversized file received an incomplete digest: %+v", evidence)
			}
		}
	}
}

func TestPersistenceReferencesAreBounded(t *testing.T) {
	data := []byte(strings.Repeat("/root/.cling &\n/usr/local/bin/.cling;\n", 200))
	if got := persistenceTargets(data, false); !reflect.DeepEqual(got, clingPaths) {
		t.Fatalf("repeated entries were not deduplicated: %+v", got)
	}
}

func TestQuotedShellSeparatorsDoNotCreatePersistence(t *testing.T) {
	for _, line := range []string{
		`echo 'disabled; /root/.cling'`,
		`printf '%s\n' 'a | /usr/local/bin/.cling'`,
		`echo "a && /root/.cling"`,
		`echo escaped\; /root/.cling`,
		`echo value # ; /root/.cling`,
	} {
		if got := persistenceTargets([]byte(line), false); len(got) != 0 {
			t.Fatalf("quoted/commented content became persistence: %q: %+v", line, got)
		}
	}
	if got := persistenceTargets([]byte(`echo 'normal; text'; exec "/root/.cling" &`), false); len(got) != 1 || got[0] != "/root/.cling" {
		t.Fatalf("unquoted execution after a separator should be retained: %+v", got)
	}
}

func TestComplexShellContentRemainsUnassessed(t *testing.T) {
	for _, script := range []string{
		"cat <<'EOF'\n/root/.cling\nEOF\n",
		"echo 'disabled\n/root/.cling\n'\n",
		"disabled() {\n/root/.cling\n}\n",
		"echo disabled \\\n/root/.cling\n",
	} {
		if got := persistenceTargets([]byte(script), false); len(got) != 0 {
			t.Fatalf("literal script content became persistence: %q: %+v", script, got)
		}
		root := t.TempDir()
		writeAuditFixture(t, root, "/etc/init.d/rcS", []byte(script), 0o755)
		observation, err := Audit(root, "192.0.2.10")
		if err != nil {
			t.Fatal(err)
		}
		if len(observation.Files) != 1 || len(observation.Persistence) != 0 || coverageFor(t, observation, "persistence:/etc/init.d/rcS").Status != "partial" {
			t.Fatal("unsupported script syntax must retain a hash and report partial persistence coverage")
		}
	}
}
