package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vedetta-network/vedetta/sensor/internal/client"
	"github.com/vedetta-network/vedetta/sensor/internal/iotsecurity"
	"github.com/vedetta-network/vedetta/sensor/internal/netinfo"
)

const securityQueueLimit = 128

type securityRuntime struct {
	capturer        *iotsecurity.Capturer
	queue           chan iotsecurity.Observation
	done            chan struct{}
	cancelProducers context.CancelFunc
	cancelDelivery  context.CancelFunc
	producers       sync.WaitGroup
	dropped         atomic.Int64
	disabled        atomic.Bool
}

func (r *sensorRun) startSecurityDetection() {
	if r.security != nil || (!r.iotEnabled && !r.iotHostAudit) || r.core == nil {
		return
	}
	producerCtx, cancelProducers := context.WithCancel(context.Background())
	deliveryCtx, cancelDelivery := context.WithCancel(context.Background())
	s := &securityRuntime{
		queue: make(chan iotsecurity.Observation, securityQueueLimit), done: make(chan struct{}),
		cancelProducers: cancelProducers, cancelDelivery: cancelDelivery,
	}
	r.security = s
	go func() {
		defer close(s.done)
		cfg := defaultSecurityPushConfig
		cfg.OnAuthorizationError = r.authorizationRejected
		pushSecurityObservations(deliveryCtx, r.core, s.queue, cfg)
		s.disabled.Store(true)
		cancelProducers()
	}()

	// DHCP and interface state can change during the sensor lifetime. Resolve
	// local attribution again for each audit and coverage report.
	currentSubject := func() string {
		interfaces, err := netinfo.ListInterfaces()
		if err != nil {
			log.Printf("WARNING: local security observation identity unavailable: %v", err)
			return ""
		}
		return securitySubjectIP(interfaces, r.iotIface, r.scanCIDR)
	}
	subject := currentSubject()
	if r.iotEnabled {
		capture, err := iotsecurity.NewCapturer(iotsecurity.Config{
			Interface: r.iotIface, CoreURL: r.coreURL, CIDR: r.scanCIDR, Promiscuous: r.iotPromiscuous, OnObservation: s.enqueue,
		})
		if err == nil {
			err = capture.Start()
		}
		if err != nil {
			log.Printf("WARNING: IoT packet detection not assessed: %v", err)
			s.reportCoverage(subject, "passive_udp", "unavailable", "Packet collection could not start; inspect sensor logs. No network compromise assessment is available.")
		} else {
			s.capturer = capture
			log.Printf("IoT packet detection active on %s; coverage is limited to traffic visible on this interface", capture.Interface())
			s.reportCoverage(subject, "passive_udp", "active", "Observes UDP 9034, 3478 and 19302 only on the capture interface. Unseen traffic is not assessed.")
		}
	} else {
		s.reportCoverage(subject, "passive_udp", "disabled", "Packet detection disabled by sensor configuration.")
	}

	if r.iotHostAudit {
		s.producers.Add(1)
		go func() {
			defer s.producers.Done()
			ticker := time.NewTicker(15 * time.Minute)
			defer ticker.Stop()
			for {
				if producerCtx.Err() != nil {
					return
				}
				observation, err := collectLocalSecurityAudit("/", currentSubject)
				if err != nil {
					log.Printf("WARNING: local IoT filesystem audit unavailable: %v", err)
					s.reportCoverage(currentSubject(), "host_filesystem", "unavailable", "Local sensor filesystem audit or current host attribution failed. Other LAN devices were not inspected.")
				} else {
					s.enqueue(observation)
				}
				select {
				case <-producerCtx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	} else {
		s.reportCoverage(subject, "host_filesystem", "disabled", "Automatic local filesystem audit is disabled or the sensor has no attributable interface IP. Remote device filesystems are not inspected.")
	}

	s.producers.Add(1)
	go func() {
		defer s.producers.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-producerCtx.Done():
				return
			case <-ticker.C:
				if dropped := s.dropped.Load(); dropped > 0 {
					log.Printf("WARNING: IoT observation queue dropped %d records; collection coverage is incomplete", dropped)
					if s.reportCoverage(currentSubject(), "security_delivery", "limited", fmt.Sprintf("Bounded queue dropped %d observations since the last queued coverage report.", dropped)) {
						s.dropped.Add(-dropped)
					}
				}
			}
		}
	}()
}

func (s *securityRuntime) enqueue(observation iotsecurity.Observation) {
	s.tryEnqueue(observation)
}

func (s *securityRuntime) tryEnqueue(observation iotsecurity.Observation) bool {
	if s.disabled.Load() {
		return false
	}
	select {
	case s.queue <- observation:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

func (s *securityRuntime) reportCoverage(subject, check, status, detail string) bool {
	if subject == "" {
		return false
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		log.Printf("WARNING: could not identify security coverage observation: %v", err)
		return false
	}
	return s.tryEnqueue(iotsecurity.Observation{
		ObservationID: hex.EncodeToString(id[:]), Timestamp: time.Now().UTC(), SubjectIP: subject,
		Kind: "coverage", Coverage: []iotsecurity.Coverage{{Check: check, Status: status, Detail: detail}},
	})
}

func (r *sensorRun) stopSecurityDetection() {
	s := r.security
	if s == nil {
		return
	}
	s.cancelProducers()
	stopped := make(chan struct{})
	go func() {
		// Close the queue only after every producer has stopped. If filesystem
		// or capture I/O stalls, the owner still has a bounded shutdown below.
		if s.capturer != nil {
			s.capturer.Stop()
		}
		s.producers.Wait()
		close(s.queue)
		<-s.done
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(6 * time.Second):
		log.Printf("WARNING: security delivery shutdown deadline reached; undelivered observations are not persisted")
		s.disabled.Store(true)
		s.cancelDelivery()
		select {
		case <-stopped:
		case <-time.After(250 * time.Millisecond):
			log.Printf("WARNING: security transport ignored cancellation during process shutdown")
		}
	}
	s.cancelDelivery()
	if dropped := s.dropped.Load(); dropped > 0 {
		log.Printf("WARNING: IoT observation queue dropped %d records before shutdown", dropped)
	}
	r.security = nil
}

func collectLocalSecurityAudit(root string, currentSubject func() string) (iotsecurity.Observation, error) {
	subject := currentSubject()
	if subject == "" {
		return iotsecurity.Observation{}, errors.New("no current local interface IP for host audit")
	}
	observation, err := iotsecurity.Audit(root, subject)
	if err != nil {
		return observation, err
	}
	if currentSubject() != subject {
		return iotsecurity.Observation{}, errors.New("local interface address changed during host audit; result not attributed")
	}
	observation.Coverage = append(observation.Coverage, iotsecurity.Coverage{Check: "audit_source", Status: "inspected", Detail: "live_sensor_root"})
	return observation, nil
}

// Only real sensor interface addresses are eligible for local-host attribution.
// The scanned target may be a different device or subnet and must not be used.
func securitySubjectIP(interfaces []netinfo.NetworkInterface, preferred, cidr string) string {
	_, subnet, _ := net.ParseCIDR(cidr)
	var fallback string
	for _, iface := range interfaces {
		if !iface.IsUp || iface.IsLoopback {
			continue
		}
		for _, raw := range iface.IPs {
			ip := net.ParseIP(raw)
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if preferred != "" && preferred != "auto" && iface.Name == preferred {
				return ip.String()
			}
			if preferred == "" || preferred == "auto" {
				if subnet != nil && subnet.Contains(ip) {
					return ip.String()
				}
			}
			if fallback == "" {
				fallback = ip.String()
			}
		}
	}
	return fallback
}

type securityPusher interface {
	PushSecurity(context.Context, []iotsecurity.Observation) error
}

type securityPushConfig struct {
	FlushInterval        time.Duration
	AttemptTimeout       time.Duration
	RetryInterval        time.Duration
	MaxRetryInterval     time.Duration
	OnAuthorizationError func(error)
}

var defaultSecurityPushConfig = securityPushConfig{
	FlushInterval: 5 * time.Second, AttemptTimeout: 3 * time.Second,
	RetryInterval: 2 * time.Second, MaxRetryInterval: time.Minute,
}

// Failed batches are kept unchanged; Core's sensor-scoped observation IDs make
// whole-batch retries safe even after partial persistence or a lost response.
// Memory is bounded to the producer channel and one eight-record batch.
func pushSecurityObservations(ctx context.Context, core securityPusher, observations <-chan iotsecurity.Observation, cfg securityPushConfig) {
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 3 * time.Second
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = 2 * time.Second
	}
	if cfg.MaxRetryInterval < cfg.RetryInterval {
		cfg.MaxRetryInterval = time.Minute
	}
	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()
	pending := make([]iotsecurity.Observation, 0, 8)
	retry := cfg.RetryInterval
	var nextAttempt time.Time
	flush := func() bool {
		if len(pending) == 0 {
			return true
		}
		attemptCtx, cancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
		err := core.PushSecurity(attemptCtx, pending)
		cancel()
		if err == nil {
			pending = pending[:0]
			retry = cfg.RetryInterval
			nextAttempt = time.Time{}
			return true
		}
		if errors.Is(err, client.ErrSecurityUnsupported) {
			log.Printf("WARNING: %v; IoT security delivery disabled for this run, coverage not assessed by Core", err)
			return false
		}
		if ctx.Err() != nil {
			return false
		}
		if client.IsAuthorizationError(err) {
			if cfg.OnAuthorizationError != nil {
				cfg.OnAuthorizationError(err)
			}
			log.Printf("WARNING: IoT security delivery stopped after credential rejection; restart after resetting enrollment. Undelivered observations are not retained.")
			return false
		}
		var status *client.HTTPStatusError
		if errors.As(err, &status) && status.StatusCode >= 400 && status.StatusCode < 500 &&
			status.StatusCode != http.StatusTooManyRequests && status.StatusCode != http.StatusRequestTimeout &&
			!client.IsAuthorizationError(err) {
			log.Printf("WARNING: Core rejected %d IoT observations: %v; records dropped and coverage incomplete", len(pending), err)
			pending = pending[:0]
			nextAttempt = time.Time{}
			return true
		}
		log.Printf("WARNING: IoT security delivery pending: %v", err)
		nextAttempt = time.Now().Add(retry)
		retry *= 2
		if retry > cfg.MaxRetryInterval {
			retry = cfg.MaxRetryInterval
		}
		return true
	}
	for {
		input := observations
		if len(pending) == cap(pending) || !nextAttempt.IsZero() {
			input = nil
		}
		select {
		case <-ctx.Done():
			return
		case observation, ok := <-input:
			if !ok {
				// The owner applies the global shutdown deadline to this context.
				for len(pending) > 0 {
					if !flush() {
						return
					}
					if len(pending) == 0 {
						return
					}
					wait := time.NewTimer(cfg.RetryInterval)
					select {
					case <-ctx.Done():
						wait.Stop()
						return
					case <-wait.C:
					}
				}
				return
			}
			pending = append(pending, observation)
			if len(pending) == cap(pending) && !time.Now().Before(nextAttempt) {
				if !flush() {
					return
				}
			}
		case <-ticker.C:
			if !time.Now().Before(nextAttempt) && !flush() {
				return
			}
		}
	}
}

func runSecurityAudit(ctx context.Context, root, subject string, submit bool, coreURL string, output io.Writer) error {
	subject = strings.TrimSpace(subject)
	if subject != "" {
		ip := net.ParseIP(subject)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("audit subject must be a unicast IP address")
		}
		subject = ip.String()
	}
	if submit && subject == "" {
		return errors.New("submission requires --iot-audit-ip identifying the inspected device")
	}
	observation, err := iotsecurity.Audit(root, subject)
	if err != nil {
		return err
	}
	observation.Coverage = append(observation.Coverage, iotsecurity.Coverage{Check: "audit_source", Status: "inspected", Detail: "explicit_filesystem"})
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(observation); err != nil {
		return fmt.Errorf("write audit result: %w", err)
	}
	if !submit {
		return nil
	}
	core, err := client.New(coreURL)
	if err != nil {
		return err
	}
	if !core.TokenConfigured() {
		return errors.New("submission requires an existing enrolled sensor credential")
	}
	submitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := core.PushSecurity(submitCtx, []iotsecurity.Observation{observation}); err != nil {
		return fmt.Errorf("submit audit: %w", err)
	}
	log.Printf("Filesystem audit submitted for the explicitly identified device; unobserved activity remains unassessed")
	return nil
}
