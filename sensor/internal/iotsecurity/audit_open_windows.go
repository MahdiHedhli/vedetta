//go:build windows

package iotsecurity

import "os"

func openAuditFile(root *os.Root, name string) (*os.File, error) {
	// Root rejects Windows device names and traversal outside the selected root.
	// The caller rejects reparse/symlink entries and rechecks the opened identity
	// and regular-file type before reading extracted firmware evidence.
	return root.Open(name)
}
