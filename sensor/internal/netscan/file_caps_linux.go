//go:build linux

package netscan

import (
	"errors"

	"golang.org/x/sys/unix"
)

func executableHasCapabilities(path string) (bool, error) {
	size, err := unix.Getxattr(path, "security.capability", nil)
	if err == nil {
		return size > 0, nil
	}
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return false, nil
	}
	return false, err
}
