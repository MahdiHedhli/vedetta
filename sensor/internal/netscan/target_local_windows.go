//go:build windows

package netscan

// ValidateLocalTarget additionally proves the native Windows backend can enumerate
// the complete target. It must fail before enrollment rather than accepting a /21+
// that later produces a healthy-looking service with no discovery results.
func ValidateLocalTarget(target string) error {
	if err := ValidateTarget(target); err != nil {
		return err
	}
	_, err := enumerateHosts(target)
	return err
}
