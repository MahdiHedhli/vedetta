//go:build windows

package iotsecurity

import "fmt"

// Windows has no native passive IoT capture backend. The portable packet parser
// and explicit extracted-filesystem audit remain available without Npcap.
type Capturer struct{}

func NewCapturer(cfg Config) (*Capturer, error) {
	return nil, fmt.Errorf("passive IoT UDP observation is unsupported on Windows; extracted-filesystem audit remains available")
}

func (c *Capturer) Start() error {
	return fmt.Errorf("passive IoT UDP observation is unsupported on Windows")
}
func (c *Capturer) Stop()             {}
func (c *Capturer) Interface() string { return "" }
