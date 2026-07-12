//go:build !windows

package client

import "os"

// securePath restricts path to owner-only access — 0600 for the token file, 0700
// for its directory — the POSIX way.
func securePath(path string, isDir bool) error {
	mode := os.FileMode(0o600)
	if isDir {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

// hasInsecurePerms reports whether a POSIX file is group- or world-accessible.
func hasInsecurePerms(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}
