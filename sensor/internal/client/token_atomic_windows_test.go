//go:build windows

package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPersistTokenBlockedReaderPreservesPriorToken(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	const oldToken = "synthetic-old-token"
	if err := os.WriteFile(tokenPath, []byte(oldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	core := &CoreClient{TokenPath: tokenPath, authToken: oldToken}

	pathPtr, err := windows.UTF16PtrFromString(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open blocking token reader: %v", err)
	}
	readerOpen := true
	defer func() {
		if readerOpen {
			_ = windows.CloseHandle(reader)
		}
	}()

	started := time.Now()
	err = core.persistToken("synthetic-new-token")
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("token replacement unexpectedly succeeded while a non-share-delete reader was open")
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("token replacement error = %v, want sharing/access conflict", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("blocked token replacement took %s, want bounded failure within 5s", elapsed)
	}
	if err := windows.CloseHandle(reader); err != nil {
		t.Fatalf("close blocking token reader: %v", err)
	}
	readerOpen = false

	if got, err := readTokenFile(tokenPath); err != nil || string(got) != oldToken {
		t.Fatalf("failed replacement changed prior on-disk token: data=%q err=%v", got, err)
	}
	if got := core.authTokenSnapshot(); got != oldToken {
		t.Fatalf("failed replacement changed in-memory token: %q", got)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sensor-token-") {
			t.Fatalf("failed replacement left temporary credential file %q", entry.Name())
		}
	}
}

func TestPersistTokenReplacesPathWhileShareDeleteReaderKeepsOldObject(t *testing.T) {
	parent := testTokenDir(t)
	tokenPath := filepath.Join(parent, "sensor-token")
	const oldToken = "synthetic-old-token"
	const newToken = "synthetic-new-token"
	if err := os.WriteFile(tokenPath, []byte(oldToken), 0o600); err != nil {
		t.Fatal(err)
	}
	core := &CoreClient{TokenPath: tokenPath, authToken: oldToken}

	pathPtr, err := windows.UTF16PtrFromString(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open share-delete token reader: %v", err)
	}
	defer func() { _ = windows.CloseHandle(reader) }()

	if err := core.persistToken(newToken); err != nil {
		t.Fatalf("replace token while share-delete reader is open: %v", err)
	}
	oldBytes := make([]byte, len(oldToken))
	var bytesRead uint32
	if err := windows.ReadFile(reader, oldBytes, &bytesRead, nil); err != nil {
		t.Fatalf("read old file object after replacement: %v", err)
	}
	if got := string(oldBytes[:bytesRead]); got != oldToken {
		t.Fatalf("existing reader saw %q after replacement, want old object %q", got, oldToken)
	}
	if got, err := readTokenFile(tokenPath); err != nil || string(got) != newToken {
		t.Fatalf("new path did not resolve to replacement: data=%q err=%v", got, err)
	}
	if got := core.authTokenSnapshot(); got != newToken {
		t.Fatalf("replacement was not activated in memory: %q", got)
	}
}

func TestReadTokenFileRejectsReparsePoint(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target-token")
	link := filepath.Join(parent, "sensor-token")
	if err := os.WriteFile(target, []byte("synthetic-target-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create Windows file symlink: %v", err)
	}

	if _, err := readTokenFile(link); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("readTokenFile reparse error = %v, want fail-closed rejection", err)
	}
}

func TestReplaceTokenFileRejectsReparseSource(t *testing.T) {
	parent := t.TempDir()
	realSource := filepath.Join(parent, "real-source")
	linkSource := filepath.Join(parent, "linked-source")
	target := filepath.Join(parent, "sensor-token")
	if err := os.WriteFile(realSource, []byte("synthetic-new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("synthetic-old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realSource, linkSource); err != nil {
		t.Skipf("cannot create Windows file symlink: %v", err)
	}

	if err := replaceTokenFile(linkSource, target); err == nil || !strings.Contains(err.Error(), "reparse-point token rename source") {
		t.Fatalf("replaceTokenFile reparse-source error = %v, want fail-closed rejection", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "synthetic-old-token" {
		t.Fatalf("reparse source changed target: data=%q err=%v", got, err)
	}
}

func TestReplaceTokenFileRejectsReparseTarget(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "replacement")
	realTarget := filepath.Join(parent, "real-target")
	linkTarget := filepath.Join(parent, "sensor-token")
	if err := os.WriteFile(source, []byte("synthetic-new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realTarget, []byte("synthetic-old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTarget, linkTarget); err != nil {
		t.Skipf("cannot create Windows file symlink: %v", err)
	}

	if err := replaceTokenFile(source, linkTarget); err == nil || !strings.Contains(err.Error(), "non-regular sensor token target") {
		t.Fatalf("replaceTokenFile reparse-target error = %v, want fail-closed rejection", err)
	}
	if got, err := os.ReadFile(realTarget); err != nil || string(got) != "synthetic-old-token" {
		t.Fatalf("reparse target changed referent: data=%q err=%v", got, err)
	}
}
