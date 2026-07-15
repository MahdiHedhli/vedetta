//go:build windows

package netscan

// ValidateLocalTarget additionally proves the native Windows backend can represent
// the complete target as one source-bound local scope. Numeric Nmap ranges/lists are
// valid for the Unix backend but can span disjoint links, so Windows rejects them
// before enrollment/work execution instead of accepting a target that later fails.
func ValidateLocalTarget(target string) error {
	if err := ValidateTarget(target); err != nil {
		return err
	}
	return validateSourceBoundWindowsTarget(target)
}
