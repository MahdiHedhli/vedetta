package iotsecurity

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	CaptureFilter       = "udp and (port 9034 or port 3478 or port 19302)"
	CorrelationWindow   = 60 * time.Second
	maxTrackedSubjects  = 256
	maxFlowsPerSubject  = 16
	maxPacketPrefix     = 128
	observationCooldown = 60 * time.Second
)

type flowKey struct {
	peer       string
	sourcePort uint16
	peerPort   uint16
}

type subjectState struct {
	lastSeen time.Time
	requests map[flowKey]PacketEvidence
	emitted  map[string]time.Time
}

// PacketDetector is a portable, concurrency-safe detector. State is bounded by
// subjects, flows, and a 60-second event-time window. It emits evidence only.
type PacketDetector struct {
	mu        sync.Mutex
	subjects  map[string]*subjectState
	watermark time.Time
}

func NewPacketDetector() *PacketDetector {
	return &PacketDetector{subjects: make(map[string]*subjectState)}
}

// ObservePacket accepts only complete unfragmented UDP packets. Packets without
// an acquisition timestamp are not usable event-time evidence. This method
// copies retained bytes, so later packet-buffer reuse cannot change observations.
func (d *PacketDetector) ObservePacket(packet gopacket.Packet) []Observation {
	evidence, payload, ok := packetEvidence(packet)
	if !ok {
		return nil
	}

	kind, subject := "", evidence.SourceIP
	switch {
	case evidence.DestinationPort == 9034 && len(payload) > 4 &&
		bytes.HasPrefix(payload, []byte("orf;")) && len(bytes.TrimSpace(payload[4:])) > 0:
		kind, subject = "realtek_exploit", evidence.DestinationIP
		// Never retain the injected commands, even as a packet prefix.
		evidence.PayloadHex = hex.EncodeToString(payload[:4])
	case stunPort(evidence.DestinationPort) && zeroIDBindingRequest(payload):
		kind = "stun_request"
		// Header fields suffice; do not retain optional credentials/attributes.
		evidence.PayloadHex = hex.EncodeToString(payload[:20])
	case stunPort(evidence.DestinationPort) && !stunEnvelope(payload) && registrationTag(payload) != "":
		kind = "cling_registration"
		evidence.PayloadHex = hex.EncodeToString(payload[:min(len(payload), maxPacketPrefix)])
	default:
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.subjects == nil {
		d.subjects = make(map[string]*subjectState)
	}
	timestamp := evidence.Timestamp
	if timestamp.Before(d.watermark.Add(-CorrelationWindow)) {
		return nil
	}
	if timestamp.After(d.watermark) {
		d.watermark = timestamp
	}
	now := d.watermark
	d.expire(now)
	var state *subjectState
	if kind == "cling_registration" {
		state = d.subjects[subject]
		if state == nil {
			return nil
		}
	} else {
		state = d.state(subject, now)
	}
	key := flowKey{evidence.DestinationIP, evidence.SourcePort, evidence.DestinationPort}

	switch kind {
	case "realtek_exploit":
		if !state.canEmit(kind, now) {
			return nil
		}
		return []Observation{newObservation(now, subject, kind, []PacketEvidence{evidence})}
	case "stun_request":
		// Keep the latest evidence for each socket/peer, with a fixed flow bound.
		if previous, exists := state.requests[key]; !exists || timestamp.After(previous.Timestamp) {
			if !exists && len(state.requests) >= maxFlowsPerSubject {
				state.evictFlow()
			}
			state.requests[key] = evidence
		}
		packets := state.fanoutEvidence()
		if len(packets) < 3 || !state.canEmit("stun_fanout", now) {
			return nil
		}
		return []Observation{newObservation(now, subject, "stun_fanout", packets)}
	case "cling_registration":
		request, exists := state.requests[key]
		if !exists || request.Timestamp.After(timestamp) || timestamp.Sub(request.Timestamp) > CorrelationWindow ||
			!state.canEmit(kind, now) {
			return nil
		}
		return []Observation{newObservation(now, subject, kind, []PacketEvidence{request, evidence})}
	}
	return nil
}

func newObservation(timestamp time.Time, subject, kind string, packets []PacketEvidence) Observation {
	return Observation{
		ObservationID: newObservationID(), Timestamp: timestamp.UTC(), SubjectIP: subject,
		Kind: kind, Packets: append([]PacketEvidence(nil), packets...),
	}
}

func newObservationID() string {
	var id [16]byte
	// crypto/rand.Read in the required Go runtime always fills the buffer or
	// terminates. No weak timestamp-only IDs are substituted on entropy failure.
	_, _ = rand.Read(id[:])
	return "iot-" + hex.EncodeToString(id[:])
}

func (d *PacketDetector) expire(now time.Time) {
	cutoff := now.Add(-CorrelationWindow)
	for ip, state := range d.subjects {
		if state.lastSeen.Before(cutoff) {
			delete(d.subjects, ip)
			continue
		}
		for key, request := range state.requests {
			if request.Timestamp.Before(cutoff) {
				delete(state.requests, key)
			}
		}
	}
}

func (d *PacketDetector) state(subject string, now time.Time) *subjectState {
	if state := d.subjects[subject]; state != nil {
		state.lastSeen = now
		return state
	}
	if len(d.subjects) >= maxTrackedSubjects {
		oldestIP := ""
		var oldest time.Time
		for ip, state := range d.subjects {
			if oldestIP == "" || state.lastSeen.Before(oldest) || (state.lastSeen.Equal(oldest) && ip < oldestIP) {
				oldestIP, oldest = ip, state.lastSeen
			}
		}
		delete(d.subjects, oldestIP)
	}
	state := &subjectState{lastSeen: now, requests: make(map[flowKey]PacketEvidence), emitted: make(map[string]time.Time)}
	d.subjects[subject] = state
	return state
}

func (s *subjectState) canEmit(kind string, now time.Time) bool {
	if previous, exists := s.emitted[kind]; exists && now.Sub(previous) < observationCooldown {
		return false
	}
	s.emitted[kind] = now
	return true
}

func (s *subjectState) evictFlow() {
	var oldestKey flowKey
	var oldest time.Time
	first := true
	for key, request := range s.requests {
		if first || request.Timestamp.Before(oldest) || (request.Timestamp.Equal(oldest) && flowLess(key, oldestKey)) {
			oldestKey, oldest, first = key, request.Timestamp, false
		}
	}
	delete(s.requests, oldestKey)
}

func flowLess(a, b flowKey) bool {
	if a.peer != b.peer {
		return a.peer < b.peer
	}
	if a.sourcePort != b.sourcePort {
		return a.sourcePort < b.sourcePort
	}
	return a.peerPort < b.peerPort
}

func (s *subjectState) fanoutEvidence() []PacketEvidence {
	byPeer := make(map[string]PacketEvidence)
	for _, request := range s.requests {
		previous, exists := byPeer[request.DestinationIP]
		if !exists || request.Timestamp.After(previous.Timestamp) {
			byPeer[request.DestinationIP] = request
		}
	}
	peers := make([]string, 0, len(byPeer))
	for peer := range byPeer {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	packets := make([]PacketEvidence, 0, len(peers))
	for _, peer := range peers {
		packets = append(packets, byPeer[peer])
	}
	return packets
}

func packetEvidence(packet gopacket.Packet) (PacketEvidence, []byte, bool) {
	if packet == nil || packet.Metadata() == nil || packet.Metadata().Truncated || packet.ErrorLayer() != nil ||
		packet.Metadata().Timestamp.IsZero() {
		return PacketEvidence{}, nil, false
	}
	metadata := packet.Metadata()
	if metadata.CaptureLength > 0 && metadata.Length > metadata.CaptureLength {
		return PacketEvidence{}, nil, false
	}
	if packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
		return PacketEvidence{}, nil, false
	}
	var src, dst net.IP
	var networkPayloadLength int
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip, ok := layer.(*layers.IPv4)
		if !ok || ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 || ip.Protocol != layers.IPProtocolUDP ||
			int(ip.Length) != len(ip.Contents)+len(ip.Payload) {
			return PacketEvidence{}, nil, false
		}
		src, dst = ip.SrcIP, ip.DstIP
		networkPayloadLength = len(ip.Payload)
	} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip, ok := layer.(*layers.IPv6)
		// Restrict to direct UDP IPv6. Extensions, fragments and jumbograms need
		// explicit future support and must not be partly interpreted as evidence.
		if !ok || ip.NextHeader != layers.IPProtocolUDP || int(ip.Length) != len(ip.Payload) {
			return PacketEvidence{}, nil, false
		}
		src, dst = ip.SrcIP, ip.DstIP
		networkPayloadLength = len(ip.Payload)
	} else {
		return PacketEvidence{}, nil, false
	}
	if len(src) == 0 || len(dst) == 0 || src.IsUnspecified() || dst.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() {
		return PacketEvidence{}, nil, false
	}
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || udp.Length < 8 || len(udp.Contents) != 8 || int(udp.Length) != 8+len(udp.Payload) || int(udp.Length) != networkPayloadLength {
		return PacketEvidence{}, nil, false
	}
	return PacketEvidence{
		Timestamp: metadata.Timestamp.UTC(), SourceIP: src.String(), DestinationIP: dst.String(),
		SourcePort: uint16(udp.SrcPort), DestinationPort: uint16(udp.DstPort), PayloadLength: len(udp.Payload),
	}, udp.Payload, true
}

func stunPort(port uint16) bool { return port == 3478 || port == 19302 }

// zeroIDBindingRequest checks the RFC 8489 envelope and all attribute lengths.
// Zero-ID responses, retransmission timing, and public server reputation do not
// independently identify a compromised host.
func zeroIDBindingRequest(payload []byte) bool {
	return validSTUNEnvelope(payload) && binary.BigEndian.Uint16(payload[:2]) == 0x0001 &&
		bytes.Equal(payload[8:20], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func validSTUNEnvelope(payload []byte) bool {
	if !stunEnvelope(payload) {
		return false
	}
	for offset := 20; offset < len(payload); {
		if len(payload)-offset < 4 {
			return false
		}
		length := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		next := offset + 4 + ((length + 3) &^ 3)
		if next > len(payload) {
			return false
		}
		offset = next
	}
	return true
}

func stunEnvelope(payload []byte) bool {
	return len(payload) >= 20 && payload[0]&0xc0 == 0 &&
		binary.BigEndian.Uint32(payload[4:8]) == 0x2112a442 &&
		int(binary.BigEndian.Uint16(payload[2:4])) == len(payload)-20 && (len(payload)-20)%4 == 0
}

func registrationTag(payload []byte) string {
	// Only a bounded prefix is inspected and retained. Token boundaries avoid
	// matching an unrelated word that merely contains an infection tag.
	prefix := payload[:min(len(payload), maxPacketPrefix)]
	for _, tag := range []string{"realtek.selfrep", "selfrep.router"} {
		start := 0
		for start < len(prefix) {
			index := bytes.Index(prefix[start:], []byte(tag))
			if index < 0 {
				break
			}
			index += start
			end := index + len(tag)
			leftOK := index == 0 || tagDelimiter(prefix[index-1])
			rightOK := (end == len(payload)) || (end < len(prefix) && tagDelimiter(prefix[end]))
			if leftOK && rightOK {
				return tag
			}
			start = index + 1
		}
	}
	return ""
}

func tagDelimiter(value byte) bool {
	switch value {
	case 0, ' ', '\t', '\r', '\n', '\v', '\f', ',', ';', ':':
		return true
	}
	return false
}
