//go:build windows

package client

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func takeOwnershipPrivilegeEnabled(t *testing.T) bool {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer token.Close()

	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		t.Fatalf("size process-token privileges: %v", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], size, &size); err != nil {
		t.Fatalf("read process-token privileges: %v", err)
	}

	name, err := windows.UTF16PtrFromString("SeTakeOwnershipPrivilege")
	if err != nil {
		t.Fatal(err)
	}
	var target windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &target); err != nil {
		t.Fatalf("look up SeTakeOwnershipPrivilege: %v", err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Luid == target {
			return privilege.Attributes&windows.SE_PRIVILEGE_ENABLED != 0
		}
	}
	t.Fatal("process token does not contain SeTakeOwnershipPrivilege")
	return false
}

func TestTakeOwnershipPrivilegeIsSerializedAndRestored(t *testing.T) {
	before := takeOwnershipPrivilegeEnabled(t)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstResult := make(chan error, 1)

	go func() {
		firstResult <- withTakeOwnershipPrivilege("first concurrency test operation", func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	select {
	case <-firstEntered:
	case err := <-firstResult:
		t.Fatalf("first privileged operation failed before entering: %v", err)
	case <-time.After(5 * time.Second):
		close(releaseFirst)
		t.Fatal("first privileged operation did not enter")
	}

	// TryLock makes the serialization assertion deterministic: a scheduler delay
	// cannot make a missing mutex look correct, as an absence-with-timeout test can.
	if takeOwnershipPrivilegeMu.TryLock() {
		takeOwnershipPrivilegeMu.Unlock()
		close(releaseFirst)
		t.Fatal("SeTakeOwnershipPrivilege mutex was not held across the privileged operation")
	}
	close(releaseFirst)

	if err := <-firstResult; err != nil {
		t.Fatalf("first privileged operation failed: %v", err)
	}
	if !takeOwnershipPrivilegeMu.TryLock() {
		t.Fatal("SeTakeOwnershipPrivilege mutex remained locked after restoration")
	}
	takeOwnershipPrivilegeMu.Unlock()
	if after := takeOwnershipPrivilegeEnabled(t); after != before {
		t.Fatalf("SeTakeOwnershipPrivilege enabled state changed: before=%t after=%t", before, after)
	}
}

func TestAdjustedPrivilegeAssignmentRejectsNotAllAssigned(t *testing.T) {
	if err := adjustedPrivilegeAssignmentError(nil); err != nil {
		t.Fatalf("successful privilege assignment rejected: %v", err)
	}
	if err := adjustedPrivilegeAssignmentError(windows.ERROR_NOT_ALL_ASSIGNED); !errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
		t.Fatalf("ERROR_NOT_ALL_ASSIGNED result = %v, want explicit rejection", err)
	}
}

// assertTokenSecured verifies the token file's NTFS owner and DACL through the
// locale-independent Windows security APIs. On Windows os.FileMode permission
// bits are synthetic (a 0600 assert is meaningless and reports 0666).
func assertTokenSecured(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read token security descriptor: %v", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatalf("read token owner: %v", err)
	}
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(owner, admins) {
		t.Fatalf("token owner = %s, want BUILTIN\\Administrators", owner.String())
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read token DACL: %v", err)
	}
	if dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("token DACL ACE count = %v, want exactly SYSTEM + Administrators", func() any {
			if dacl == nil {
				return "nil"
			}
			return dacl.AceCount
		}())
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read token DACL control flags: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("token DACL inherits permissions; want a protected DACL")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	foundSystem, foundAdmins := false, false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatalf("read token ACE %d: %v", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != windows.NO_INHERITANCE || ace.Mask != fileFullControl {
			t.Fatalf("token ACE %d is not exact allow/full-control/no-inheritance policy", i)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case windows.EqualSid(sid, system):
			if foundSystem {
				t.Fatal("token DACL contains duplicate LocalSystem ACEs")
			}
			foundSystem = true
		case windows.EqualSid(sid, admins):
			if foundAdmins {
				t.Fatal("token DACL contains duplicate Administrators ACEs")
			}
			foundAdmins = true
		default:
			t.Fatalf("token DACL contains unexpected trustee %s", sid.String())
		}
	}
	if !foundSystem || !foundAdmins {
		t.Fatal("token DACL is missing LocalSystem or Administrators")
	}
}

func TestSecurePathReplacesAttackerACEAndOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor-token")
	if err := os.WriteFile(path, []byte("synthetic-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Model a lower-privileged pre-creator with an explicit ACE. The remediation
	// must replace, not augment, that DACL and must transfer ownership as well.
	if out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(F)").CombinedOutput(); err != nil {
		t.Fatalf("seed Everyone ACE: %v\n%s", err, out)
	}
	if err := securePath(path, false); err != nil {
		t.Fatalf("secure pre-created token: %v", err)
	}
	assertTokenSecured(t, path)
}

func TestEnsureSecureDirectoryCreatesExactDescriptor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatalf("create protected token directory: %v", err)
	}
	if err := verifySecurePath(dir, true); err != nil {
		t.Fatalf("verify protected token directory: %v", err)
	}
	// The final descriptor must be idempotently accepted on upgrades.
	if err := ensureSecureDirectory(dir); err != nil {
		t.Fatalf("verify existing protected token directory: %v", err)
	}
}

func TestEnsureSecureDirectoryRejectsUnexpectedExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Vedetta")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)(F)").CombinedOutput(); err != nil {
		t.Fatalf("seed Everyone directory ACE: %v\n%s", err, out)
	}
	if err := ensureSecureDirectory(dir); err == nil || !strings.Contains(err.Error(), "not the trusted Vedetta directory") {
		t.Fatalf("unexpected existing directory error = %v, want fail-closed rejection", err)
	}
	// Rejection must not silently repair the attacker's object in place.
	if out, err := exec.Command("icacls", dir).CombinedOutput(); err != nil || !strings.Contains(string(out), "Everyone") {
		t.Fatalf("untrusted directory was mutated or became unreadable: err=%v\n%s", err, out)
	}
}

func TestEnsureSecureDirectoryRejectsReparsePoint(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	link := filepath.Join(parent, "Vedetta")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		// Directory junctions do not require Developer Mode and exercise the same
		// FILE_ATTRIBUTE_REPARSE_POINT boundary on older CI images.
		if out, junctionErr := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); junctionErr != nil {
			t.Skipf("cannot create Windows reparse point: symlink=%v junction=%v (%s)", err, junctionErr, out)
		}
	}
	if err := ensureSecureDirectory(link); err == nil {
		t.Fatal("reparse-point token directory accepted")
	}
}

func TestEnsureSecureDirectoryRejectsAncestorReparsePoint(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target-parent")
	link := filepath.Join(parent, "linked-parent")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if out, junctionErr := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); junctionErr != nil {
			t.Skipf("cannot create Windows ancestor reparse point: symlink=%v junction=%v (%s)", err, junctionErr, out)
		}
	}
	tokenDir := filepath.Join(link, "Vedetta")
	if err := ensureSecureDirectory(tokenDir); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("ancestor reparse-point error = %v, want fail-closed rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "Vedetta")); !os.IsNotExist(err) {
		t.Fatalf("ancestor reparse target was mutated: %v", err)
	}
}

func TestClearPersistedTokenRecoversMalformedLeafWithoutFollowingIt(t *testing.T) {
	tokenPath := testTokenPath(t)
	if err := os.WriteFile(tokenPath, []byte("malformed-dacl"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", tokenPath, "/grant", "*S-1-1-0:(F)").CombinedOutput(); err != nil {
		t.Fatalf("seed malformed token DACL: %v\n%s", err, out)
	}
	if err := ClearPersistedToken(); err != nil {
		t.Fatalf("clear malformed token leaf: %v", err)
	}
	if _, err := os.Lstat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("malformed token leaf remained: %v", err)
	}

	target := filepath.Join(filepath.Dir(tokenPath), "unrelated-secret")
	if err := os.WriteFile(target, []byte("must-survive-reset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, tokenPath); err != nil {
		t.Skipf("cannot create Windows token symlink: %v", err)
	}
	if err := ClearPersistedToken(); err != nil {
		t.Fatalf("clear token symlink: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "must-survive-reset" {
		t.Fatalf("reset changed symlink referent: data=%q err=%v", data, err)
	}
}
