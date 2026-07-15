//go:build !linux && !windows

package netscan

func executableHasCapabilities(string) (bool, error) { return false, nil }
