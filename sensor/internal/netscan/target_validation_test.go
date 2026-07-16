package netscan

import (
	"reflect"
	"strings"
	"testing"
)

func TestNmapOctetCardinalityStopsAtLimitWithoutExpansion(t *testing.T) {
	octet := strings.Repeat("0-255,", 8) + "0-255"
	count, err := nmapOctetCardinality(octet, 1024)
	if err != nil {
		t.Fatalf("count bounded octet: %v", err)
	}
	if count != 1025 {
		t.Fatalf("bounded cardinality = %d, want capped sentinel 1025", count)
	}
	if _, err := expandNmapOctet(octet, 1024); err == nil {
		t.Fatal("bounded expansion accepted an octet above its limit")
	}
}

func TestNmapMembershipValidatesSuffixAfterEarlyMatch(t *testing.T) {
	// The candidate matches the first value in the third octet, but the later
	// 999 must still make the whole target invalid.
	if targetContainsIPv4("192.0.2,999.7", "192.0.2.7") {
		t.Fatal("membership accepted an invalid suffix after an early match")
	}
}

func TestNmapNumericTargetLengthIsBounded(t *testing.T) {
	octet := strings.Repeat("1,", maxNmapNumericTargetBytes/2) + "1"
	target := "192.0.2." + octet
	if err := ValidateTarget(target); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("overlong numeric target error = %v, want length rejection", err)
	}
	if got := nmapRangeBreadth(target); got <= maxScanAddresses {
		t.Fatalf("overlong numeric target breadth = %d, want fail-closed sentinel", got)
	}
	if targetContainsIPv4(target, "192.0.2.1") {
		t.Fatal("overlong numeric target passed membership validation")
	}
}

func TestNmapMembershipEnforcesGlobalBreadthBoundary(t *testing.T) {
	if !targetContainsIPv4("10.0-255.0-255.0-255", "10.255.255.255") {
		t.Fatal("membership rejected the exact 2^24-address boundary")
	}
	if targetContainsIPv4("0-1.0-255.0-255.0-255", "1.255.255.255") {
		t.Fatal("membership accepted a target above the 2^24-address boundary")
	}
}

func TestNmapExpansionPreservesOrderAndDuplicates(t *testing.T) {
	got, err := enumerateNmapIPv4Target("192.0.2.3,1-2,2", 1024)
	if err != nil {
		t.Fatalf("enumerate ordered target: %v", err)
	}
	want := []string{"192.0.2.3", "192.0.2.1", "192.0.2.2", "192.0.2.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enumeration = %v, want %v", got, want)
	}
}
