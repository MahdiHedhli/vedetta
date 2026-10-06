//go:build !windows

package iotsecurity

import (
	"os"
	"syscall"
)

func openAuditFile(root *os.Root, name string) (*os.File, error) {
	// Nonblocking protects against a racing FIFO replacement. No-follow rejects
	// a racing final symlink. The caller checks regular-file type and identity
	// again before reading; Root confines parent-directory resolution.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
