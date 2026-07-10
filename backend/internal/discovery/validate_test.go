package discovery

// GHSA-c5gj: nmap option/argument injection. ValidateScanTarget must accept only
// clean scan targets (bare IP, CIDR, nmap numeric range, strict DNS hostname) and
// reject anything that begins with "-", contains whitespace, or contains a shell
// metacharacter. Synthetic values only.

import "testing"

func TestValidateScanTarget_Accepts(t *testing.T) {
	valid := []string{
		"192.168.1.1",          // bare IPv4
		"2001:db8::1",          // bare IPv6
		"192.168.1.0/24",       // IPv4 CIDR
		"2001:db8::/32",        // IPv6 CIDR
		"10.0.0.1-50",          // nmap octet range
		"192.168.1.1-254",      // nmap octet range
		"10.0.0.1,2,3",         // nmap octet list
		"10.0.0-255.1-10",      // nmap multi-octet range
		"router.local",         // strict DNS hostname
		"host-1.example.com",   // hostname with hyphen mid-label
	}
	for _, target := range valid {
		if err := ValidateScanTarget(target); err != nil {
			t.Errorf("expected %q to be accepted, got error: %v", target, err)
		}
	}
}

func TestValidateScanTarget_Rejects(t *testing.T) {
	invalid := []string{
		"",                       // empty
		"-oG",                    // leading dash → nmap flag injection
		"-192.168.1.1",           // leading dash
		"--script=http-vuln",     // leading dash
		"192.168.1.1 -oG /tmp/x", // whitespace + flag smuggling
		"192.168.1.1;rm -rf /",   // shell metachar ;
		"192.168.1.1|cat",        // pipe
		"192.168.1.1&whoami",     // ampersand
		"$(whoami)",              // command substitution
		"`id`",                   // backticks
		"host>out",               // redirection
		"a<b",                    // redirection
		"foo(bar)",               // parens
		"host'name",              // single quote
		"host\"name",             // double quote
		"10.0.0.1\t50",           // embedded tab
	}
	for _, target := range invalid {
		if err := ValidateScanTarget(target); err == nil {
			t.Errorf("expected %q to be rejected, but it was accepted", target)
		}
	}
}
