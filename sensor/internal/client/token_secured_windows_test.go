//go:build windows

package client

import (
	"os/exec"
	"strings"
	"testing"
)

// assertTokenSecured verifies the token file's NTFS DACL is restricted to SYSTEM +
// Administrators. On Windows os.FileMode permission bits are synthetic (a 0600 assert is
// meaningless and reports 0666), so access is enforced by the DACL that securePath
// applies via icacls. This checks icacls grants SYSTEM and Administrators and does NOT
// grant any broad principal (Everyone / BUILTIN\Users / Authenticated Users).
func assertTokenSecured(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", path, err, out)
	}
	acl := string(out)
	for _, want := range []string{`NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`} {
		if !strings.Contains(acl, want) {
			t.Fatalf("token DACL missing %q:\n%s", want, acl)
		}
	}
	for _, bad := range []string{"Everyone", `BUILTIN\Users`, "Authenticated Users"} {
		if strings.Contains(acl, bad) {
			t.Fatalf("token DACL unexpectedly grants %q:\n%s", bad, acl)
		}
	}
}
