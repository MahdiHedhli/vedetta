//go:build !windows

package client

import "os"

func replaceTokenFile(from, to string) error {
	return os.Rename(from, to)
}

func syncTokenDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
