package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func TestGetCorpusProfileReturnsAtomicRepresentationAndETag(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	profile, err := db.CreateCorpusProfile(ctx, corpusProfileRequest(), CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(ctx, profile.ProfileID, corpusVariantRequest("atomic"),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variantRevisionID := profile.Variants[0].Draft.VariantRevisionID

	// Pause while SQLite prepares the variant-revision hydration query, then
	// queue a mutation. Once that query closes its rows, a non-transactional
	// reader yields the sole connection to the queued writer before it can read
	// evidence and the ETag. A transaction must instead keep the writer out until
	// the complete representation and ETag have been read from one snapshot.
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var blockOnce sync.Once
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Raw(func(driverConn any) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("unexpected SQLite driver connection %T", driverConn)
		}
		sqliteConn.RegisterAuthorizer(func(operation int, table, column, _ string) int {
			if operation == sqlite3.SQLITE_READ && table == "device_corpus_variant_revisions" && column == "status" {
				blockOnce.Do(func() {
					close(blocked)
					<-release
				})
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		cleanupConn, cleanupErr := db.Conn(context.Background())
		if cleanupErr != nil {
			return
		}
		_ = cleanupConn.Raw(func(driverConn any) error {
			if sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn); ok {
				sqliteConn.RegisterAuthorizer(nil)
			}
			return nil
		})
		_ = cleanupConn.Close()
	})

	type readResult struct {
		profile *corpus.Profile
		err     error
	}
	readDone := make(chan readResult, 1)
	go func() {
		got, readErr := db.GetCorpusProfile(ctx, profile.ProfileID)
		readDone <- readResult{profile: got, err: readErr}
	}()

	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("detail read did not reach the ETag interleave point")
	}

	baselineWaits := db.Stats().WaitCount
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := db.ExecContext(ctx, `UPDATE device_corpus_variant_revisions
			SET status = 'superseded' WHERE variant_revision_id = ?`, variantRevisionID)
		writeDone <- writeErr
	}()
	deadline := time.Now().Add(2 * time.Second)
	for db.Stats().WaitCount == baselineWaits && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if db.Stats().WaitCount == baselineWaits {
		t.Fatal("mutation did not queue behind the detail transaction")
	}
	releaseOnce.Do(func() { close(release) })

	var result readResult
	select {
	case result = <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("detail read did not complete")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.profile.Variants[0].Draft == nil || result.profile.Variants[0].Draft.Status != "draft" {
		t.Fatalf("detail representation crossed snapshots: %+v", result.profile.Variants[0])
	}
	if want := corpusProfileValueETag(result.profile); result.profile.ETag != want {
		t.Fatalf("detail ETag %q does not describe its own revision ledger %q", result.profile.ETag, want)
	}

	select {
	case err = <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("queued mutation did not complete")
	}
	if err != nil {
		t.Fatal(err)
	}
	after, err := db.GetCorpusProfile(ctx, profile.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ETag == result.profile.ETag {
		t.Fatal("mutation did not change the profile ETag")
	}
	if after.Variants[0].Draft != nil || after.Variants[0].History[0].Status != "superseded" {
		t.Fatalf("queued mutation was not visible after the atomic read: %+v", after.Variants[0])
	}
}

func corpusProfileValueETag(profile *corpus.Profile) string {
	parts := []string{"profile:" + profile.ProfileID}
	profileHistory := append([]corpus.ProfileRevision(nil), profile.History...)
	sort.Slice(profileHistory, func(i, j int) bool { return profileHistory[i].Revision < profileHistory[j].Revision })
	for _, revision := range profileHistory {
		parts = append(parts, "p:"+revision.ProfileRevisionID+":"+revision.Status)
	}
	variants := append([]corpus.Variant(nil), profile.Variants...)
	sort.Slice(variants, func(i, j int) bool { return variants[i].VariantID < variants[j].VariantID })
	for _, variant := range variants {
		history := append([]corpus.VariantRevision(nil), variant.History...)
		sort.Slice(history, func(i, j int) bool { return history[i].Revision < history[j].Revision })
		for _, revision := range history {
			parts = append(parts, "v:"+variant.VariantID+":"+variant.VariantKey+":"+
				variant.PredecessorVariantID+":"+revision.VariantRevisionID+":"+revision.Status)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}
