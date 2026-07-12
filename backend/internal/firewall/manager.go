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

// DeviceSink is called with connector-discovered clients for device-registry
// enrichment (never creates events). Optional; when nil, inventory sync is off.
type DeviceSink func(clients []ClientInfo) error

// ClientLister is implemented by connectors that can enumerate connected clients
// for device-inventory enrichment (e.g. the UniFi REST connector).
type ClientLister interface {
	ListClients(ctx context.Context) ([]ClientInfo, error)
}

// Manager coordinates multiple firewall connectors.
type Manager struct {
	connectors     map[string]Connector
	configs        map[string]ConnectorConfig
	sink           EventSink
	deviceSink     DeviceSink
	inventoryEvery time.Duration
	mu             sync.RWMutex
	stopChs        map[string]chan struct{}
	sinkErrors     map[string]string
	running        bool
}

// NewManager creates a new firewall manager with the provided event sink.
func NewManager(sink EventSink) *Manager {
	return &Manager{
		connectors:     make(map[string]Connector),
		configs:        make(map[string]ConnectorConfig),
		sink:           sink,
		inventoryEvery: 300 * time.Second,
		stopChs:        make(map[string]chan struct{}),
		sinkErrors:     make(map[string]string),
	}
}

// SetDeviceSink enables client-inventory sync into the device registry, polled
// every interval (default 300s). Call before Start.
func (m *Manager) SetDeviceSink(sink DeviceSink, interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceSink = sink
	if interval > 0 {
		m.inventoryEvery = interval
	}
}

// Register registers a firewall connector with its configuration.
func (m *Manager) Register(cfg ConnectorConfig, conn Connector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectors[cfg.Name] = conn
	m.configs[cfg.Name] = cfg
	delete(m.sinkErrors, cfg.Name)
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

		// Client-inventory sync (enrichment only) for connectors that support it.
		if lister, ok := conn.(ClientLister); ok && m.deviceSink != nil {
			invStop := make(chan struct{})
			m.stopChs[name+":inventory"] = invStop
			go m.inventoryLoop(name, lister, m.inventoryEvery, invStop)
		}
	}
	m.running = true
	return nil
}

// inventoryLoop periodically syncs connector clients into the device registry.
func (m *Manager) inventoryLoop(name string, lister ClientLister, interval time.Duration, stop chan struct{}) {
	if interval <= 0 {
		interval = 300 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("Firewall connector %q inventory sync every %s", name, interval)

	// Run one sync promptly so the registry is populated without waiting a full interval.
	m.doInventory(name, lister)
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.doInventory(name, lister)
		}
	}
}

// doInventory performs a single client-inventory sync.
func (m *Manager) doInventory(name string, lister ClientLister) {
	m.mu.RLock()
	sink := m.deviceSink
	m.mu.RUnlock()
	if sink == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	clients, err := lister.ListClients(ctx)
	cancel()
	if err != nil {
		log.Printf("Firewall connector %q inventory error: %v", name, err)
		return
	}
	if len(clients) == 0 {
		return
	}
	if err := sink(clients); err != nil {
		log.Printf("Firewall connector %q device sink error: %v", name, err)
		return
	}
	log.Printf("Firewall connector %q synced %d clients to device registry", name, len(clients))
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
		m.mu.Lock()
		m.sinkErrors[name] = fmt.Sprintf("Core event persistence failed: %v", err)
		m.mu.Unlock()
		log.Printf("Firewall connector %q sink error: %v", name, err)
		return
	}
	m.mu.Lock()
	delete(m.sinkErrors, name)
	m.mu.Unlock()
	if acknowledger, ok := conn.(EventAcknowledger); ok {
		acknowledger.AcknowledgeEvents(events)
	}

	log.Printf("Firewall connector %q ingested %d events", name, len(vedettaEvents))
}

// List returns the health status of all registered connectors.
func (m *Manager) List() []ConnectorHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []ConnectorHealth
	for name, conn := range m.connectors {
		out = append(out, m.connectorHealthLocked(name, conn))
	}
	return out
}

// NamedHealth pairs a connector's configured name and type with its health, for
// the admin connectors API (spec 001, T4.4).
type NamedHealth struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Health ConnectorHealth `json:"health"`
}

// ListNamed returns the health of all registered connectors with their names.
func (m *Manager) ListNamed() []NamedHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]NamedHealth, 0, len(m.connectors))
	for name, conn := range m.connectors {
		out = append(out, NamedHealth{
			Name:   name,
			Type:   m.configs[name].Type,
			Health: m.connectorHealthLocked(name, conn),
		})
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
	return m.connectorHealthLocked(name, conn), nil
}

// connectorHealthLocked overlays Core-side persistence failures on transport
// health reported by the connector. A successful controller HTTP poll is not a
// successful collection cycle until the unified processor commits its events.
// Caller must hold m.mu for reading.
func (m *Manager) connectorHealthLocked(name string, conn Connector) ConnectorHealth {
	health := conn.Health()
	if sinkError := m.sinkErrors[name]; sinkError != "" {
		health.LastError = sinkError
	}
	return health
}
