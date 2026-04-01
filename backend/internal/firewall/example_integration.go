package firewall

import (
	"context"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

// MockConnector is a simple mock connector for testing without real hardware.
type MockConnector struct {
	mockEvents []FirewallEvent
	cfg        ConnectorConfig
	connected  bool
}

// NewMockConnector creates a mock firewall connector for testing.
func NewMockConnector(cfg ConnectorConfig, events []FirewallEvent) *MockConnector {
	return &MockConnector{
		cfg:        cfg,
		mockEvents: events,
	}
}

func (mc *MockConnector) Name() string                                     { return "mock" }
func (mc *MockConnector) Connect(_ context.Context) error                  { mc.connected = true; return nil }
func (mc *MockConnector) Disconnect() error                                { mc.connected = false; return nil }
func (mc *MockConnector) Poll(_ context.Context) ([]FirewallEvent, error)  { return mc.mockEvents, nil }

func (mc *MockConnector) Discover(_ context.Context) (*FirewallInfo, error) {
	return &FirewallInfo{
		Model:    "Mock Firewall",
		Firmware: "1.0",
		Features: []string{"firewall", "test"},
	}, nil
}

func (mc *MockConnector) Health() ConnectorHealth {
	return ConnectorHealth{
		Connected:  mc.connected,
		EventCount: int64(len(mc.mockEvents)),
	}
}

// Ensure MockConnector satisfies Connector interface at compile time.
var _ Connector = (*MockConnector)(nil)

// Ensure models import is used (for EventSink type compatibility check).
var _ EventSink = func(_ []models.Event) error { return nil }

// ExampleCreateMockSetup demonstrates testing with mock connectors.
func ExampleCreateMockSetup() *Manager {
	events := []FirewallEvent{
		{
			Timestamp: time.Now(),
			Action:    "block",
			Protocol:  "tcp",
			SrcIP:     "192.168.1.100",
			DstIP:     "8.8.8.8",
			DstPort:   443,
			Rule:      "block_c2",
		},
	}

	cfg := ConnectorConfig{
		Name:         "test_mock",
		Type:         "mock",
		PollInterval: 10 * time.Second,
		Enabled:      true,
	}
	m := NewManager(func(_ []models.Event) error { return nil })
	m.Register(cfg, NewMockConnector(cfg, events))
	return m
}
