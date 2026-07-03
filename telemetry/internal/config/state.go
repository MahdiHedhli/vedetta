package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// State-file helpers. Telemetry keeps its state as flat, versioned JSON files
// inside the state dir (no SQLite, no migration). Writes are atomic
// (tmp + rename) and secret files are created 0600. Corrupt files are treated
// as absent so the daemon regenerates them (always safe: worst case is
// re-registration or re-reading recent events, absorbed by idempotency).

// StateFileVersion is the current on-disk schema version for state JSON files.
const StateFileVersion = 1

// EnsureStateDir creates the state directory (0700) if missing.
func EnsureStateDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

// WriteJSONFile atomically writes v as indented JSON to path with the given
// permission bits. It writes to a temp file in the same directory then renames.
func WriteJSONFile(path string, v any, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before rename.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Ensure perms survive even if umask affected the temp file.
	return os.Chmod(path, perm)
}

// ReadJSONFile reads and decodes JSON from path into v. It returns
// (found=false, nil) when the file is missing OR corrupt, so callers can treat
// both as "regenerate". A genuine IO error (e.g. permission denied) is returned.
func ReadJSONFile(path string, v any) (found bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		// Corrupt file: treat as absent so the daemon regenerates it.
		return false, nil
	}
	return true, nil
}

// WriteSecretBytes atomically writes raw bytes (e.g. the HMAC salt) with 0600.
func WriteSecretBytes(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// CheckVersion validates a state file's version field, returning an error only
// on a version newer than we understand (older/equal is fine, we migrate up).
func CheckVersion(name string, v int) error {
	if v > StateFileVersion {
		return fmt.Errorf("%s has newer state version %d (max %d)", name, v, StateFileVersion)
	}
	return nil
}
