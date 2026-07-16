package corpusmatch

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// PreparedCorpus is a parsed matcher generation that has not yet changed active process
// state. Activate is infallible so OUI and corpus consumers can both validate before either
// publishes a newly switched device-DB generation.
type PreparedCorpus struct {
	managedPath *string
	matcher     *Matcher
}

// Activate publishes a previously prepared immutable matcher.
func (p *PreparedCorpus) Activate() {
	if p == nil {
		return
	}
	if p.managedPath != nil {
		managedPath.Store(p.managedPath)
	}
	setActive(p.matcher)
}

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
func PrepareManagedCorpus(installDir string) (*PreparedCorpus, error) {
	installDir = strings.TrimSpace(installDir)
	if installDir == "" {
		return nil, fmt.Errorf("corpusmatch: managed install directory is empty")
	}
	path := filepath.Join(installDir, managedCorpusFile)
	matcher, err := prepareFromPath(path)
	if err != nil {
		return nil, err
	}
	stablePath := path
	return &PreparedCorpus{managedPath: &stablePath, matcher: matcher}, nil
}

// EnableManagedCorpus prepares and publishes the managed corpus. Coordinators activating
// multiple files should instead prepare every consumer before calling Activate.
func EnableManagedCorpus(installDir string) error {
	prepared, err := PrepareManagedCorpus(installDir)
	if err != nil {
		return err
	}
	prepared.Activate()
	return nil
}

// ReloadCorpus re-reads the managed snapshot after the updater switches generations. Returning
// an error rolls the generation pointer back (OnInstalled contract); an absent file just
// clears the active corpus to reflect the new generation.
func PrepareReloadCorpus() (*PreparedCorpus, error) {
	p := managedPath.Load()
	if p == nil {
		return nil, nil // not managed
	}
	matcher, err := prepareFromPath(*p)
	if err != nil {
		return nil, err
	}
	return &PreparedCorpus{matcher: matcher}, nil
}

// ReloadCorpus prepares and publishes the current managed snapshot.
func ReloadCorpus() error {
	prepared, err := PrepareReloadCorpus()
	if err != nil {
		return err
	}
	prepared.Activate()
	return nil
}

// loadFromPath loads (or clears) the active matcher from a snapshot file, bounding the read
// so an oversized file cannot exhaust memory before ParseSnapshot's byte check.
func prepareFromPath(path string) (*Matcher, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewMatcher(nil), nil // no corpus shipped in this generation
		}
		return nil, fmt.Errorf("corpusmatch: open %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("corpusmatch: read %s: %w", path, err)
	}
	snap, err := ParseSnapshot(data)
	if err != nil {
		return nil, err
	}
	return NewMatcher(snap), nil
}

func setActive(m *Matcher) {
	managedMu.Lock()
	activeMatcher = m
	managedMu.Unlock()
}
