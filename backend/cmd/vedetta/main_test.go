package main

import "testing"

func TestEnvEnabled(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"1", "true", "TRUE", " yes ", "on"} {
		if !envEnabled(value) {
			t.Errorf("envEnabled(%q) = false", value)
		}
	}
	for _, value := range []string{"", "0", "false", "disabled"} {
		if envEnabled(value) {
			t.Errorf("envEnabled(%q) = true", value)
		}
	}
}
