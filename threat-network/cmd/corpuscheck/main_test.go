package main

import "testing"

const bootstrapSnapshot = `{"schema_version":1,"corpus_revision":0,"generated_at":"2026-07-16T00:00:00Z","profiles":[]}`

func TestValidateSnapshot(t *testing.T) {
	if err := validateSnapshot([]byte(bootstrapSnapshot)); err != nil {
		t.Fatalf("valid bootstrap snapshot rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"unknown field": bootstrapSnapshot[:len(bootstrapSnapshot)-1] + `,"private_extension":"must-not-ship"}`,
		"trailing JSON": bootstrapSnapshot + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSnapshot([]byte(raw)); err == nil {
				t.Fatalf("validator accepted %s", name)
			}
		})
	}
}
