package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCorpusWriteContextCancellationDoesNotQueueOrMutate(t *testing.T) {
	db := newTestDB(t)

	// Open configures exactly one SQLite connection. Holding it here makes the
	// corpus write wait in database/sql before BeginTx can return, which is the
	// production head-of-line case request cancellation must release.
	blocker, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	blocked := true
	defer func() {
		if blocked {
			_ = blocker.Rollback()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := make(chan error, 1)
	go func() {
		_, writeErr := db.CreateCorpusProfile(ctx, corpusProfileRequest(), CorpusMutation{})
		result <- writeErr
	}()
	select {
	case err = <-result:
	case <-time.After(time.Second):
		// Release the fixture before failing so even a regression that ignores
		// ctx cannot strand a goroutine and the database cleanup indefinitely.
		_ = blocker.Rollback()
		blocked = false
		err = <-result
		t.Fatalf("queued corpus write did not return on cancellation; eventual error = %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued corpus write error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("queued corpus write ignored cancellation for %s", elapsed)
	}

	if err = blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	blocked = false

	var profiles, audits int
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM device_corpus_profiles`).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM device_corpus_audit`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if profiles != 0 || audits != 0 {
		t.Fatalf("canceled queued write persisted profiles=%d audits=%d", profiles, audits)
	}
}

func TestCorpusCanceledReadLeavesSingleConnectionReusable(t *testing.T) {
	db := newTestDB(t)
	profile, err := db.CreateCorpusProfile(context.Background(), corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = db.GetCorpusProfile(ctx, profile.ProfileID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled corpus read error = %v, want context canceled", err)
	}

	got, err := db.GetCorpusProfile(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatalf("database was not reusable after canceled read: %v", err)
	}
	if got.ProfileID != profile.ProfileID {
		t.Fatalf("reusable read profile = %q, want %q", got.ProfileID, profile.ProfileID)
	}
}

func TestCorpusSnapshotLoadWaitHonorsCancellation(t *testing.T) {
	db := newTestDB(t)

	// Hold the cold-cache singleflight gate directly so the request reaches the
	// exact wait that must remain interruptible even though the SQLite
	// connection itself is available.
	db.corpusLoadGate <- struct{}{}
	gateHeld := true
	defer func() {
		if gateHeld {
			<-db.corpusLoadGate
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, _, err := db.CurrentCorpusSnapshot(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued snapshot load error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("queued snapshot load ignored cancellation for %s", elapsed)
	}

	<-db.corpusLoadGate
	gateHeld = false
	if _, _, err := db.CurrentCorpusSnapshot(context.Background()); err != nil {
		t.Fatalf("snapshot load failed after canceled waiter: %v", err)
	}
}
