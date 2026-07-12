//go:build windows

package client

import (
	"fmt"
	"os"
	"os/exec"
)

// securePath restricts path so that only LocalSystem (SID S-1-5-18) and the
// Administrators group (S-1-5-32-544) have access — the NTFS equivalent of the
// 0600/0700 intent, which os.Chmod cannot express (on Windows it only toggles the
// read-only bit, so the token would otherwise stay world-readable). Inheritance is
// removed (/inheritance:r) so a permissive %ProgramData% ACL cannot widen it, and
// well-known SIDs are used so it works regardless of the OS display language.
// LocalSystem is granted because the sensor runs as a LocalSystem service and must
// still read its own token.
func securePath(path string, isDir bool) error {
	out, err := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:(F)",     // NT AUTHORITY\SYSTEM
		"/grant:r", "*S-1-5-32-544:(F)", // BUILTIN\Administrators
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %w: %s", path, err, string(out))
	}
	return nil
}

// hasInsecurePerms is a POSIX concept; on NTFS, access is governed by the ACL set
// in securePath rather than the synthesized Go mode bits, so this never triggers a
// re-permission on Windows.
func hasInsecurePerms(os.FileMode) bool { return false }
