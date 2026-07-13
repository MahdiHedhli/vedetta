package store

import (
	"errors"
	"sync"
	"testing"

	"github.com/vedetta-network/vedetta/threat-network/internal/corpus"
)

func createPublishedCorpusTestProfile(t *testing.T, db *DB, model string, expectedRevision int) (*corpus.Profile, string) {
	t.Helper()
	req := corpusProfileRequest()
	req.Labels.Model = model
	profile, err := db.CreateCorpusProfile(req, CorpusMutation{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err = db.CreateCorpusVariant(profile.ProfileID, corpusVariantRequest("initial"),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	variantID := profile.Variants[0].VariantID
	profile, err = db.PublishCorpusProfile(profile.ProfileID, corpusPublishRequest(expectedRevision),
		CorpusMutation{ExpectedETag: profile.ETag})
	if err != nil {
		t.Fatal(err)
	}
	return profile, variantID
}

func corpusMutationCounts(t *testing.T, db *DB) (audit, releases int) {
	t.Helper()
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_audit`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_corpus_releases`).Scan(&releases); err != nil {
		t.Fatal(err)
	}
	return audit, releases
}

func assertCorpusReleaseState(t *testing.T, db *DB, revision, audit, releases int) {
	t.Helper()
	manifest, err := db.CorpusManifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.CorpusRevision != revision {
		t.Fatalf("corpus revision = %d, want %d", manifest.CorpusRevision, revision)
	}
	gotAudit, gotReleases := corpusMutationCounts(t, db)
	if gotAudit != audit || gotReleases != releases {
		t.Fatalf("audit/releases = %d/%d, want %d/%d", gotAudit, gotReleases, audit, releases)
	}
}

func TestCorpusLifecycleRejectsInterveningReleaseFromAnotherProfile(t *testing.T) {
	t.Run("retire profile", func(t *testing.T) {
		db := newTestDB(t)
		target, _ := createPublishedCorpusTestProfile(t, db, "Lifecycle Retire A", 0)
		createPublishedCorpusTestProfile(t, db, "Lifecycle Retire B", 1)
		auditBefore, releasesBefore := corpusMutationCounts(t, db)

		_, err := db.RetireCorpusProfile(target.ProfileID,
			corpusLifecycleRequest("obsolete_product", 1),
			CorpusMutation{ExpectedETag: target.ETag})
		if !errors.Is(err, ErrCorpusRevisionConflict) {
			t.Fatalf("stale retire error = %v, want ErrCorpusRevisionConflict", err)
		}
		assertCorpusReleaseState(t, db, 2, auditBefore, releasesBefore)
		unchanged, err := db.GetCorpusProfile(target.ProfileID)
		if err != nil {
			t.Fatal(err)
		}
		if unchanged.ETag != target.ETag || unchanged.Published == nil || unchanged.Draft != nil {
			t.Fatalf("stale retire changed target profile: %+v", unchanged)
		}

		if _, err = db.RetireCorpusProfile(target.ProfileID,
			corpusLifecycleRequest("obsolete_product", 2),
			CorpusMutation{ExpectedETag: target.ETag}); err != nil {
			t.Fatalf("current retire failed: %v", err)
		}
		assertCorpusReleaseState(t, db, 3, auditBefore+1, releasesBefore+1)
	})

	t.Run("withdraw variant", func(t *testing.T) {
		db := newTestDB(t)
		target, variantID := createPublishedCorpusTestProfile(t, db, "Lifecycle Withdraw A", 0)
		createPublishedCorpusTestProfile(t, db, "Lifecycle Withdraw B", 1)
		auditBefore, releasesBefore := corpusMutationCounts(t, db)

		_, err := db.WithdrawCorpusVariant(variantID,
			corpusLifecycleRequest("privacy_withdrawal", 1),
			CorpusMutation{ExpectedETag: target.ETag})
		if !errors.Is(err, ErrCorpusRevisionConflict) {
			t.Fatalf("stale withdrawal error = %v, want ErrCorpusRevisionConflict", err)
		}
		assertCorpusReleaseState(t, db, 2, auditBefore, releasesBefore)
		unchanged, err := db.GetCorpusProfile(target.ProfileID)
		if err != nil {
			t.Fatal(err)
		}
		if unchanged.ETag != target.ETag || len(unchanged.Variants) != 1 || unchanged.Variants[0].Published == nil {
			t.Fatalf("stale withdrawal changed target variant: %+v", unchanged)
		}

		if _, err = db.WithdrawCorpusVariant(variantID,
			corpusLifecycleRequest("privacy_withdrawal", 2),
			CorpusMutation{ExpectedETag: target.ETag}); err != nil {
			t.Fatalf("current withdrawal failed: %v", err)
		}
		assertCorpusReleaseState(t, db, 3, auditBefore+1, releasesBefore+1)
	})
}

func TestConcurrentCorpusLifecycleActionsCreateOnlyOneReviewedRelease(t *testing.T) {
	db := newTestDB(t)
	retireTarget, _ := createPublishedCorpusTestProfile(t, db, "Concurrent Lifecycle Retire", 0)
	withdrawTarget, variantID := createPublishedCorpusTestProfile(t, db, "Concurrent Lifecycle Withdraw", 1)
	auditBefore, releasesBefore := corpusMutationCounts(t, db)

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := db.RetireCorpusProfile(retireTarget.ProfileID,
			corpusLifecycleRequest("obsolete_product", 2),
			CorpusMutation{ExpectedETag: retireTarget.ETag})
		results <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := db.WithdrawCorpusVariant(variantID,
			corpusLifecycleRequest("privacy_withdrawal", 2),
			CorpusMutation{ExpectedETag: withdrawTarget.ETag})
		results <- err
	}()
	close(start)
	wg.Wait()
	close(results)

	var succeeded, conflicted int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrCorpusRevisionConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent lifecycle error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent lifecycle results succeeded/conflicted = %d/%d, want 1/1", succeeded, conflicted)
	}
	assertCorpusReleaseState(t, db, 3, auditBefore+1, releasesBefore+1)
}
