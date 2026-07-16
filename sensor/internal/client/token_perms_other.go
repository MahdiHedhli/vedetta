//go:build !windows

package client

import (
	"fmt"
	"os"
	"syscall"
)

// ensureSecureDirectory creates only the final, dedicated token directory.  It
// deliberately does not use MkdirAll and never repairs an existing path in
// place: chmod'ing an environment-selected parent could change a shared or
// security-sensitive directory such as /etc, /root, or a user's home.
func ensureSecureDirectory(path string) error {
	if path == "" {
		return fmt.Errorf("secure directory path is empty")
	}
	if _, err := os.Lstat(path); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect token directory %s: %w", path, err)
		}
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create protected token directory %s: %w", path, err)
		}
	}
	return verifySecurePath(path, true)
}

// securePath verifies the owner-only invariant. Newly-created temporary token
// files already have mode 0600; existing paths are never chmod'd because the
// caller may have selected an unrelated path through the environment.
func securePath(path string, isDir bool) error {
	return verifySecurePath(path, isDir)
}

func verifySecurePath(path string, isDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	return verifySecureFileInfo(path, info, isDir)
}

// verifySecureFileInfo applies the exact token owner/type/mode invariant to
// metadata obtained either by Lstat or from an already-open descriptor. Keeping
// one policy avoids a path check and descriptor check drifting apart.
func verifySecureFileInfo(path string, info os.FileInfo, isDir bool) error {
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink token path %s", path)
	}
	if isDir {
		if !mode.IsDir() {
			return fmt.Errorf("token directory path %s is not a directory", path)
		}
	} else if !mode.IsRegular() {
		return fmt.Errorf("sensor token path %s is not a regular file", path)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of token path %s", path)
	}
	if owner := int(stat.Uid); owner != os.Geteuid() {
		return fmt.Errorf("token path %s is owned by uid %d, want effective uid %d", path, owner, os.Geteuid())
	}

	want := os.FileMode(0o600)
	if isDir {
		want = 0o700
	}
	if got := mode.Perm(); got != want {
		return fmt.Errorf("token path %s has mode %#o, want %#o; refusing to change an existing path", path, got, want)
	}
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("token path %s has unexpected special permission bits", path)
	}
	return nil
}

// Always perform exact lstat/owner/type/mode verification before token reads.
// Looking only at permission bits would miss a 0600 symlink to another file.
func hasInsecurePerms(os.FileMode) bool { return true }
