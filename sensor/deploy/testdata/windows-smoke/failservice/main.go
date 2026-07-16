package main

import (
	"fmt"
	"os"
)

// This fixture deliberately is not a Windows service. It passes the installer's
// side-effect-free candidate checks, then exits immediately when the SCM launches
// it without --version or --check. That forces the real rollback path.
func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Println("vedetta-sensor windows-smoke-failed-service")
			return
		case "--check":
			fmt.Println("preflight OK (intentional Windows smoke fixture)")
			return
		}
	}
	os.Exit(42)
}
