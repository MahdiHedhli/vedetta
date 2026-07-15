//go:build windows

package netscan

import "testing"

func TestValidateLocalTargetEnforcesNativeWindowsSweepCap(t *testing.T) {
	for _, target := range []string{"192.0.2.7", "198.51.100.0/22"} {
		if err := ValidateLocalTarget(target); err != nil {
			t.Errorf("supported Windows target %q rejected: %v", target, err)
		}
	}
	for _, target := range []string{
		"198.51.96.0/21", "2001:db8::/64", "999.0.0.1",
		"192.0.2.1-20", "192.0.2.1,3-4",
	} {
		if err := ValidateLocalTarget(target); err == nil {
			t.Errorf("unsupported Windows target %q accepted", target)
		}
	}
}
