package dnsingest

import (
	"sync"
)

// EventSink is a function type that DNS sources call to submit events for storage.
type EventSink func(query DNSQuery) error

// DNSSource is the interface all DNS capture methods implement.
type DNSSource interface {
	Name() string // e.g. "pihole", "passive_capture", "embedded_resolver", "adguard"
	Start() error
	Stop()
}

// Manager holds and coordinates multiple DNS sources.
type Manager struct {
	sources []DNSSource
	sink    EventSink
	mu      sync.Mutex
	running bool
}

// NewManager creates a new DNS source manager.
func NewManager(sink EventSink) *Manager {
	return &Manager{
		sources: []DNSSource{},
		sink:    sink,
		running: false,
	}
}

// Register adds a DNS source to the manager.
func (m *Manager) Register(source DNSSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources = append(m.sources, source)
}

// Start begins all registered DNS sources.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	for _, source := range m.sources {
		if err := source.Start(); err != nil {
			return err
		}
	}

	m.running = true
	return nil
}

// Stop gracefully stops all registered DNS sources.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	for _, source := range m.sources {
		source.Stop()
	}

	m.running = false
}

// GetEventSink returns the event sink used by sources.
func (m *Manager) GetEventSink() EventSink {
	return m.sink
}
