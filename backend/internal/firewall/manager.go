package firewall

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// EventSink is called when new firewall events are ready for storage.
type EventSink func(events []models.Event) error

// Manager coordinates multiple firewall connectors.
type Manager struct {
	connectors map[string]Connector
	configs    map[string]ConnectorConfig
	sink       EventSink
	mu         sync.RWMutex
	stopChs    map[string]chan struct{}
	running    bool
}

// NewManager creates a new firewall manager with the provided event sink.
func NewManager(sink EventSink) *Manager {
	return &Manager{
		connectors: make(map[string]Connector),
		configs:    make(map[string]ConnectorConfig),
		sink:       sink,
		stopChs:    make(map[string]chan struct{}),
	}
}

// Register registers a firewall connector with its configuration.
func (m *Manager) Register(cfg ConnectorConfig, conn Connector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectors[cfg.Name] = conn
	m.configs[cfg.Name] = cfg
}

// Start begins polling all enabled firewall connectors.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}

	for name, conn := range m.connectors {
		cfg := m.configs[name]
		if !cfg.Enabled {
			log.Printf("Firewall connector %q is disabled, skipping", name)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := conn.Connect(ctx); err != nil {
			cancel()
			log.Printf("Firewall connector %q failed to connect: %v", name, err)
			continue
		}
		cancel()

		stopCh := make(chan struct{})
		m.stopChs[name] = stopCh
		go m.pollLoop(name, conn, cfg.PollInterval, stopCh)
	}
	m.running = true
	return nil
}

// Stop gracefully stops all firewall connectors.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, ch := range m.stopChs {
		close(ch)
		if conn, ok := m.connectors[name]; ok {
			conn.Disconnect()
		}
	}
	m.stopChs = make(map[string]chan struct{})
	m.running = false
}

// pollLoop runs the polling loop for a single connector.
func (m *Manager) pollLoop(name string, conn Connector, interval time.Duration, stop chan struct{}) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("Firewall connector %q polling every %s", name, interval)

	for {
		select {
		case <-stop:
			log.Printf("Firewall connector %q polling stopped", name)
			return
		case <-ticker.C:
			m.doPoll(name, conn)
		}
	}
}

// doPoll performs a single poll cycle for a connector.
func (m *Manager) doPoll(name string, conn Connector) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	events, err := conn.Poll(ctx)
	cancel()

	if err != nil {
		log.Printf("Firewall connector %q poll error: %v", name, err)
		return
	}

	if len(events) == 0 {
		return
	}

	// Convert FirewallEvents to Vedetta Events
	vedettaEvents := make([]models.Event, 0, len(events))
	for _, fe := range events {
		vedettaEvents = append(vedettaEvents, fe.ToEvent(""))
	}

	// Submit to sink
	if err := m.sink(vedettaEvents); err != nil {
		log.Printf("Firewall connector %q sink error: %v", name, err)
		return
	}

	log.Printf("Firewall connector %q ingested %d events", name, len(vedettaEvents))
}

// List returns the health status of all registered connectors.
func (m *Manager) List() []ConnectorHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []ConnectorHealth
	for _, conn := range m.connectors {
		out = append(out, conn.Health())
	}
	return out
}

// Health returns the health status of a specific connector by name.
func (m *Manager) Health(name string) (ConnectorHealth, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conn, ok := m.connectors[name]
	if !ok {
		return ConnectorHealth{}, fmt.Errorf("connector %q not found", name)
	}
	return conn.Health(), nil
}
