package transmit

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Spool is a bounded on-disk queue of gzip'd batches awaiting (re)transmission.
// It is best-effort: when the cap is exceeded, the OLDEST batches are dropped
// (telemetry is not the SIEM — losing a batch here is acceptable).
type Spool struct {
	Dir         string
	MaxBatches  int           // e.g. 50
	MaxAge      time.Duration // e.g. 24h
	RejectedDir string        // poison-pill 4xx batches (capped separately)
	MaxRejected int           // e.g. 5
}

// NewSpool builds a spool rooted at stateDir/spool with contract defaults.
func NewSpool(stateDir string) *Spool {
	return &Spool{
		Dir:         filepath.Join(stateDir, "spool"),
		MaxBatches:  50,
		MaxAge:      24 * time.Hour,
		RejectedDir: filepath.Join(stateDir, "spool", "rejected"),
		MaxRejected: 5,
	}
}

// Add writes a gzip'd batch to the spool then enforces the bound (drop oldest).
// The filename encodes creation time so ordering is lexicographic.
func (s *Spool) Add(batchID string, gz []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	name := spoolName(batchID)
	if err := os.WriteFile(filepath.Join(s.Dir, name), gz, 0o600); err != nil {
		return err
	}
	return s.enforce()
}

// AddRejected moves a 4xx (poison-pill) batch to the rejected dir for operator
// inspection, capped at MaxRejected (drop oldest).
func (s *Spool) AddRejected(batchID string, gz []byte) error {
	if err := os.MkdirAll(s.RejectedDir, 0o700); err != nil {
		return err
	}
	name := spoolName(batchID)
	if err := os.WriteFile(filepath.Join(s.RejectedDir, name), gz, 0o600); err != nil {
		return err
	}
	return enforceCap(s.RejectedDir, s.MaxRejected, 0)
}

// SpooledBatch is one entry read back from the spool.
type SpooledBatch struct {
	Path string
	GZ   []byte
}

// List returns spooled batches oldest-first (excluding the rejected subdir).
func (s *Spool) List() ([]SpooledBatch, error) {
	entries, err := listSpoolFiles(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []SpooledBatch
	for _, p := range entries {
		gz, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		out = append(out, SpooledBatch{Path: p, GZ: gz})
	}
	return out, nil
}

// Remove deletes a spooled batch after successful transmission.
func (s *Spool) Remove(path string) error {
	return os.Remove(path)
}

// Depth reports the number of batches currently spooled (excluding rejected).
func (s *Spool) Depth() int {
	entries, err := listSpoolFiles(s.Dir)
	if err != nil {
		return 0
	}
	return len(entries)
}

// enforce drops batches over the count cap or older than MaxAge.
func (s *Spool) enforce() error {
	return enforceCap(s.Dir, s.MaxBatches, s.MaxAge)
}

func spoolName(batchID string) string {
	// Nanosecond timestamp prefix guarantees lexicographic == chronological.
	return time.Now().UTC().Format("20060102T150405.000000000") + "_" + sanitize(batchID) + ".json.gz"
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '_'
	}, s)
}

// listSpoolFiles returns *.json.gz paths in dir (non-recursive), sorted oldest-first.
func listSpoolFiles(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		if strings.HasSuffix(de.Name(), ".json.gz") {
			names = append(names, de.Name())
		}
	}
	sort.Strings(names) // lexicographic == chronological by prefix
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = filepath.Join(dir, n)
	}
	return paths, nil
}

// enforceCap drops oldest files until at most maxCount remain, and drops any
// older than maxAge (when maxAge > 0).
func enforceCap(dir string, maxCount int, maxAge time.Duration) error {
	paths, err := listSpoolFiles(dir)
	if err != nil {
		return err
	}
	// Age-based pruning.
	if maxAge > 0 {
		cutoff := time.Now().UTC().Add(-maxAge)
		kept := paths[:0]
		for _, p := range paths {
			if info, err := os.Stat(p); err == nil && info.ModTime().UTC().Before(cutoff) {
				_ = os.Remove(p)
				continue
			}
			kept = append(kept, p)
		}
		paths = kept
	}
	// Count-based pruning (drop oldest first).
	if maxCount > 0 && len(paths) > maxCount {
		drop := len(paths) - maxCount
		for _, p := range paths[:drop] {
			_ = os.Remove(p)
		}
	}
	return nil
}
