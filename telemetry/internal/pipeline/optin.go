package pipeline

import (
	"path/filepath"

	"github.com/vedetta-network/vedetta/telemetry/internal/config"
)

// optInFile is the state-dir file that durably records the last EFFECTIVE
// telemetry opt-in successfully read from Core. It lives next to the cursor and
// salt so an explicit admin opt-out survives a daemon restart even if Core is
// briefly unreachable at startup (GHSA-c776): without it, a restart during a
// Core blip would forget a prior OFF state, fall back to the env default (on),
// and drain queued batches — failing OPEN on a privacy control.
const optInFile = "optin.json"

// persistedOptIn is the on-disk shape for the last-known effective opt-in.
type persistedOptIn struct {
	Version int  `json:"version"`
	OptIn   bool `json:"opt_in"`
}

// loadPersistedOptIn reads the last-known effective opt-in from the state dir.
// It returns (value, true) only when a well-formed value has ever been written;
// a missing, corrupt, or too-new file yields (false, false) so the caller keeps
// treating the value as "never observed" and falls back to the env default.
func loadPersistedOptIn(stateDir string) (value bool, ok bool) {
	var p persistedOptIn
	found, err := config.ReadJSONFile(filepath.Join(stateDir, optInFile), &p)
	if err != nil || !found {
		return false, false
	}
	if err := config.CheckVersion(optInFile, p.Version); err != nil {
		return false, false
	}
	return p.OptIn, true
}

// persistOptIn atomically records the last-known effective opt-in (0644 — this
// is a policy flag, not a secret). Any write error is returned so the caller can
// surface it; it never blocks the tick.
func persistOptIn(stateDir string, optIn bool) error {
	p := persistedOptIn{Version: config.StateFileVersion, OptIn: optIn}
	return config.WriteJSONFile(filepath.Join(stateDir, optInFile), p, 0o644)
}
