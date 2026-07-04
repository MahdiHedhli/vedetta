package transmit

import "os"

// readSaltFile reads the raw salt bytes. Returns an error if missing/unreadable.
func readSaltFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
