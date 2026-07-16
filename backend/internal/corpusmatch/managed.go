package corpusmatch

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// managedCorpusFile is the snapshot filename inside an updater-managed generation directory.
const managedCorpusFile = "corpus.json"

var (
	managedMu     sync.RWMutex
	activeMatcher = NewMatcher(nil) // never nil; empty until a snapshot loads
	managedPath   atomic.Pointer[string]
)

// Active returns the current matcher. It is never nil — before any snapshot is installed
// (or when a bundle ships no corpus) it is an empty matcher that never matches — so callers
// can use corpusmatch.Active().Match(...) unconditionally.
func Active() *Matcher {
	managedMu.RLock()
	defer managedMu.RUnlock()
	return activeMatcher
}

// EnableManagedCorpus points the matcher at a signed corpus snapshot the device-DB updater
// installs at <installDir>/corpus.json, loading it if present. The corpus is OPTIONAL in a
// bundle, so an absent file is the "no corpus" state (empty matcher, no error) rather than a
// failure — an OUI-only bundle is valid. A present-but-unparseable snapshot is an error.
func EnableManagedCorpus(installDir string) error {
	path := filepath.Join(installDir, managedCorpusFile)
	managedPath.Store(&path)
	return loadFromPath(path)
}

// ReloadCorpus re-reads the managed snapshot after the updater switches generations. Returning
// an error rolls the generation pointer back (OnInstalled contract); an absent file just
// clears the active corpus to reflect the new generation.
func ReloadCorpus() error {
	p := managedPath.Load()
	if p == nil {
		return nil // not managed
	}
	return loadFromPath(*p)
}

// loadFromPath loads (or clears) the active matcher from a snapshot file, bounding the read
// so an oversized file cannot exhaust memory before ParseSnapshot's byte check.
func loadFromPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			setActive(NewMatcher(nil)) // no corpus shipped in this generation
			return nil
		}
		return fmt.Errorf("corpusmatch: open %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSnapshotBytes+1))
	if err != nil {
		return fmt.Errorf("corpusmatch: read %s: %w", path, err)
	}
	snap, err := ParseSnapshot(data)
	if err != nil {
		return err
	}
	setActive(NewMatcher(snap))
	return nil
}

func setActive(m *Matcher) {
	managedMu.Lock()
	activeMatcher = m
	managedMu.Unlock()
}
