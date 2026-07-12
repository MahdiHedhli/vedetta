//go:build windows

package dnscap

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

const etwSessionName = "VedettaDnsCapture"

// Capturer captures THIS host's DNS via the Microsoft-Windows-DNS-Client ETW
// provider — no libpcap, no Npcap, no cgo. It is a host-scoped endpoint capturer:
// it sees the OS resolver's queries (event 3006) and responses (3008), not other
// devices' traffic. A real-time ETW session needs an elevated token, which the
// sensor has when it runs as a LocalSystem service.
type Capturer struct {
	onQuery func(Query)

	mu       sync.Mutex
	running  bool
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	cancel   context.CancelFunc
	doneCh   chan struct{}
}

// NewCapturer creates a Windows ETW DNS capturer. Config.Interface/Filter/CIDR are
// ignored — ETW is host-scoped, not bound to a NIC.
func NewCapturer(cfg Config) (*Capturer, error) {
	return &Capturer{
		onQuery: cfg.OnQuery,
		doneCh:  make(chan struct{}),
	}, nil
}

// Start opens a real-time ETW session on the DNS-Client provider and begins
// consuming events. Returns an error (with an elevation hint) if the session or
// consumer cannot start.
func (c *Capturer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("capturer already running")
	}

	session := etw.NewRealTimeSession(etwSessionName)
	if err := session.EnableProvider(etw.MustParseProvider("Microsoft-Windows-DNS-Client")); err != nil {
		session.Stop()
		return fmt.Errorf("enable Microsoft-Windows-DNS-Client ETW provider (run elevated / as a service): %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	consumer := etw.NewRealTimeConsumer(ctx)
	consumer.FromSessions(session)
	if err := consumer.Start(); err != nil {
		cancel()
		session.Stop()
		return fmt.Errorf("start ETW consumer: %w", err)
	}

	c.session = session
	c.consumer = consumer
	c.cancel = cancel
	c.running = true
	go c.run()
	log.Printf("dnscap: ETW capturer started (Microsoft-Windows-DNS-Client, host-scoped)")
	return nil
}

func (c *Capturer) run() {
	defer close(c.doneCh)
	for e := range c.consumer.Events {
		if q := c.eventToQuery(e); q != nil && c.onQuery != nil {
			c.onQuery(*q)
		}
	}
}

// Interface returns a descriptive source name (ETW has no NIC binding).
func (c *Capturer) Interface() string {
	return "etw:Microsoft-Windows-DNS-Client"
}

// Stop tears down the consumer and ETW session and waits for the run loop to drain.
func (c *Capturer) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	consumer, session, cancel := c.consumer, c.session, c.cancel
	c.mu.Unlock()

	if consumer != nil {
		consumer.Stop() // closes consumer.Events, ending run()
	}
	if cancel != nil {
		cancel()
	}
	if session != nil {
		session.Stop()
	}
	<-c.doneCh
	log.Printf("dnscap: ETW capturer stopped")
}

// eventToQuery maps a DNS-Client ETW event to a Query. Event 3006 is a query
// (name + type); 3008 is the response (name + type + resolved answers). Other
// event IDs (3009/3016/3020/…) are internal resolver bookkeeping and are ignored.
func (c *Capturer) eventToQuery(e *etw.Event) *Query {
	id := e.System.EventID
	if id != 3006 && id != 3008 {
		return nil
	}
	name := strings.TrimSpace(strings.TrimSuffix(eventStr(e, "QueryName"), "."))
	if name == "" {
		return nil
	}
	q := &Query{
		Timestamp: time.Now(),
		Domain:    name,
		QueryType: dnsTypeName(eventStr(e, "QueryType")),
		Source:    "etw_dns_client",
	}
	if id == 3008 {
		q.Answers = parseQueryResults(eventStr(e, "QueryResults"))
	}
	return q
}

// eventStr pulls a string property out of an ETW event's EventData map.
func eventStr(e *etw.Event, key string) string {
	if e == nil || e.EventData == nil {
		return ""
	}
	if v, ok := e.EventData[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// dnsTypeName and parseQueryResults are defined in dns_parse.go (shared/untagged,
// so they are unit-testable on any platform).
