package transmit

import (
	"testing"
	"time"
)

func TestSpoolBoundDropsOldest(t *testing.T) {
	dir := t.TempDir()
	s := NewSpool(dir)
	s.MaxBatches = 3

	for i := 0; i < 6; i++ {
		if err := s.Add("batch", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond) // ensure distinct nanosecond prefixes
	}
	if d := s.Depth(); d != 3 {
		t.Fatalf("spool depth = %d, want 3 (oldest dropped)", d)
	}
	items, _ := s.List()
	// The three surviving batches should be the LAST three added (values 3,4,5).
	if len(items) != 3 {
		t.Fatalf("list len = %d", len(items))
	}
	if items[0].GZ[0] != 3 || items[2].GZ[0] != 5 {
		t.Errorf("wrong batches survived: %v %v", items[0].GZ, items[2].GZ)
	}
}

func TestSpoolRejectedCap(t *testing.T) {
	dir := t.TempDir()
	s := NewSpool(dir)
	s.MaxRejected = 2
	for i := 0; i < 5; i++ {
		s.AddRejected("b", []byte{byte(i)})
		time.Sleep(time.Millisecond)
	}
	files, _ := listSpoolFiles(s.RejectedDir)
	if len(files) != 2 {
		t.Errorf("rejected spool = %d files, want 2", len(files))
	}
}

func TestSpoolAgeEviction(t *testing.T) {
	dir := t.TempDir()
	s := NewSpool(dir)
	s.MaxAge = time.Nanosecond // everything is immediately stale
	s.Add("old", []byte{1})
	time.Sleep(2 * time.Millisecond)
	s.Add("new", []byte{2}) // triggers enforce which evicts the aged one
	// The "old" batch should be gone; but "new" was just written, so it may
	// survive the same enforce pass if its mtime is after cutoff.
	if d := s.Depth(); d > 1 {
		t.Errorf("age eviction failed: depth %d", d)
	}
}

func TestSpoolRemove(t *testing.T) {
	dir := t.TempDir()
	s := NewSpool(dir)
	s.Add("b", []byte{1})
	items, _ := s.List()
	if len(items) != 1 {
		t.Fatal("expected 1")
	}
	if err := s.Remove(items[0].Path); err != nil {
		t.Fatal(err)
	}
	if s.Depth() != 0 {
		t.Errorf("remove failed")
	}
}
