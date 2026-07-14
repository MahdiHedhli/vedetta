package netscan

import (
	"testing"
	"time"
)

func TestNewSourceDefaults(t *testing.T) {
	if got := NewSource(SourceConfig{}).cfg.PollInterval; got != defaultARPPollInterval {
		t.Errorf("poll interval = %v, want default %v", got, defaultARPPollInterval)
	}
	// A supplied CIDR must be preserved (not overwritten by auto-detect).
	if got := NewSource(SourceConfig{CIDR: "192.0.2.0/24", PollInterval: time.Minute}).cfg.CIDR; got != "192.0.2.0/24" {
		t.Errorf("CIDR = %q, want preserved", got)
	}
}

func TestSourceLifecycle(t *testing.T) {
	s := NewSource(SourceConfig{
		PollInterval: 10 * time.Millisecond,
		OnHost:       func(DiscoveredHost) {}, // real readNeighbors; contents don't matter here
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("second Start should error while already running")
	}

	// Stop must drain and return promptly (mirrors passive.Capturer.Stop), not hang.
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s")
	}

	s.Stop() // idempotent after stopped
}

func TestSourceNoRestartAfterStop(t *testing.T) {
	// A Source is single-use: the lifecycle channels are closed once, so a Start after
	// Stop must return an error rather than re-running loop() and panicking on a
	// double close(doneCh).
	s := NewSource(SourceConfig{PollInterval: 10 * time.Millisecond, OnHost: func(DiscoveredHost) {}})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()
	if err := s.Start(); err == nil {
		t.Fatal("Start after Stop should error (single-use), got nil")
	}
}
