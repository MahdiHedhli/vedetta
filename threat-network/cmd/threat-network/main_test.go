package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

type blockingShutdowner struct {
	started   chan struct{}
	release   <-chan struct{}
	completed chan struct{}
}

type errorShutdowner struct {
	err error
}

func (s errorShutdowner) Shutdown(context.Context) error {
	return s.err
}

func (s *blockingShutdowner) Shutdown(ctx context.Context) error {
	close(s.started)
	defer close(s.completed)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitForShutdownSignal(t *testing.T, ctx context.Context, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
	}
}

func newCommandTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func installCorruptCorpusRelease(t *testing.T, db *store.DB) {
	t.Helper()
	// The JSON is internally valid, but the persisted profile count is not. It
	// therefore reaches the same release-integrity check used during startup.
	raw := `{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[]}`
	digest := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(digest[:])
	if _, err := db.Exec(`INSERT INTO device_corpus_releases
		(corpus_revision, schema_version, snapshot_sha256, snapshot_json,
		 profile_count, variant_count, created_at)
		VALUES (1, 1, ?, ?, 1, 0, '2026-07-13T16:00:00Z')`, hash, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_corpus_state SET current_revision = 1,
		current_snapshot_sha256 = ?, updated_at = '2026-07-13T16:00:00Z'
		WHERE singleton = 1`, hash); err != nil {
		t.Fatal(err)
	}
}

func createCommandTestReporter(t *testing.T, db *store.DB) {
	t.Helper()
	if err := db.CreateReporter("reporter-test", strings.Repeat("0", 64), `[]`, "0.1.0"); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareRunModeDispatchesEarlyExitCommandsBeforeCorpusValidation(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *store.DB)
		mode  runMode
		check func(*testing.T, *store.DB)
	}{
		{
			name:  "denylist",
			setup: func(t *testing.T, db *store.DB) { createCommandTestReporter(t, db) },
			mode:  runMode{denylist: "reporter-test", reason: "recovery-test"},
			check: func(t *testing.T, db *store.DB) {
				reporter, err := db.GetReporter("reporter-test")
				if err != nil {
					t.Fatal(err)
				}
				if reporter.Status != "denylisted" {
					t.Fatalf("reporter status = %q, want denylisted", reporter.Status)
				}
			},
		},
		{
			name: "reinstate",
			setup: func(t *testing.T, db *store.DB) {
				createCommandTestReporter(t, db)
				if err := db.DenylistReporter("reporter-test", "setup"); err != nil {
					t.Fatal(err)
				}
			},
			mode: runMode{reinstate: "reporter-test"},
			check: func(t *testing.T, db *store.DB) {
				reporter, err := db.GetReporter("reporter-test")
				if err != nil {
					t.Fatal(err)
				}
				if reporter.Status != "active" {
					t.Fatalf("reporter status = %q, want active", reporter.Status)
				}
			},
		},
		{
			name:  "consensus once",
			setup: func(*testing.T, *store.DB) {},
			mode:  runMode{consensusOnce: true},
			check: func(*testing.T, *store.DB) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newCommandTestDB(t)
			tt.setup(t, db)
			installCorruptCorpusRelease(t, db)

			if _, _, err := db.CurrentCorpusSnapshot(context.Background()); err == nil {
				t.Fatal("test setup did not corrupt the current corpus release")
			}
			handled, err := prepareRunMode(db, tt.mode)
			if err != nil {
				t.Fatalf("early-exit command was blocked by corrupt corpus: %v", err)
			}
			if !handled {
				t.Fatal("early-exit command was not dispatched")
			}
			tt.check(t, db)
		})
	}
}

func TestPrepareRunModeFailsDaemonStartupClosedOnCorruptCorpus(t *testing.T) {
	db := newCommandTestDB(t)
	installCorruptCorpusRelease(t, db)

	handled, err := prepareRunMode(db, runMode{})
	if handled {
		t.Fatal("daemon startup was treated as an early-exit command")
	}
	if err == nil || !strings.Contains(err.Error(), "validate current device corpus release") {
		t.Fatalf("daemon startup error = %v, want corpus validation failure", err)
	}
}

func TestValidateAdminListenAddr(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		allow bool
		ok    bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:9091", ok: true},
		{name: "ipv6 loopback", addr: "[::1]:9091", ok: true},
		{name: "wildcard refused", addr: "0.0.0.0:9091"},
		{name: "empty wildcard refused", addr: ":9091"},
		{name: "ipv6 wildcard refused", addr: "[::]:9091"},
		{name: "hostname refused", addr: "localhost:9091"},
		{name: "nonloopback explicit opt in", addr: "192.0.2.10:9091", allow: true, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdminListenAddr(tt.addr, tt.allow)
			if (err == nil) != tt.ok {
				t.Fatalf("validateAdminListenAddr(%q, %t) error=%v, want ok=%t", tt.addr, tt.allow, err, tt.ok)
			}
		})
	}
}

func TestShutdownHTTPServersStartsAllServersConcurrently(t *testing.T) {
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	first := &blockingShutdowner{
		started:   make(chan struct{}),
		release:   firstRelease,
		completed: make(chan struct{}),
	}
	second := &blockingShutdowner{
		started:   make(chan struct{}),
		release:   secondRelease,
		completed: make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- shutdownHTTPServers(ctx, first, second)
	}()

	for index, started := range []<-chan struct{}{first.started, second.started} {
		waitForShutdownSignal(t, ctx, started, fmt.Sprintf("shutdown %d to start concurrently", index+1))
	}

	close(firstRelease)
	waitForShutdownSignal(t, ctx, first.completed, "first shutdown to complete")
	select {
	case <-done:
		t.Fatal("shutdownHTTPServers returned before the second shutdown completed")
	default:
	}

	close(secondRelease)
	waitForShutdownSignal(t, ctx, second.completed, "second shutdown to complete")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdownHTTPServers returned an unexpected error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for shutdownHTTPServers to return: %v", ctx.Err())
	}
}

func TestShutdownHTTPServersReturnsEveryFailure(t *testing.T) {
	firstErr := errors.New("public shutdown failed")
	secondErr := errors.New("admin shutdown failed")
	err := shutdownHTTPServers(context.Background(),
		errorShutdowner{err: firstErr}, errorShutdowner{err: secondErr})
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("shutdown error = %v, want both server failures", err)
	}
}

func TestHTTPWriteTimeoutAccommodatesMaximumCorpusSnapshot(t *testing.T) {
	const (
		maximumSnapshotBytes  = 16 << 20
		minimumBytesPerSecond = 128 << 10
	)
	minimumDuration := time.Duration(maximumSnapshotBytes/minimumBytesPerSecond) * time.Second
	if httpWriteTimeout < minimumDuration {
		t.Fatalf("write timeout %s cannot deliver a 16 MiB snapshot at 128 KiB/s; need at least %s",
			httpWriteTimeout, minimumDuration)
	}
}
