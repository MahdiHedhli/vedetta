//go:build !windows

package netscan

// ValidateLocalTarget applies the target grammar for the local Unix Nmap backend.
func ValidateLocalTarget(target string) error { return ValidateTarget(target) }
