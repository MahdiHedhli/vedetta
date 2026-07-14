//go:build !windows

package client

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readTokenFile(path string) ([]byte, error) {
	// Open once, refuse to follow the final symlink, and make special files
	// non-blocking so a raced FIFO cannot hang the service before validation.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap sensor token descriptor")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := verifySecureFileInfo(path, info, false); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}
