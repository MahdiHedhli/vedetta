package iotsecurity

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var packetTime = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func udpFixture(t *testing.T, timestamp time.Time, src, dst string, sourcePort, destinationPort uint16, payload []byte) gopacket.Packet {
	t.Helper()
	udp := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: layers.UDPPort(destinationPort)}
	var network gopacket.NetworkLayer
	var layer gopacket.SerializableLayer
	var first gopacket.LayerType
	if net.ParseIP(src).To4() != nil {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
		network, layer, first = ip, ip, layers.LayerTypeIPv4
	} else {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
		network, layer, first = ip, ip, layers.LayerTypeIPv6
	}
	if err := udp.SetNetworkLayerForChecksum(network); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, layer, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), first, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return packet
}

func stunFixture(zero bool) []byte {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[:2], 0x0001)
	binary.BigEndian.PutUint32(payload[4:8], 0x2112a442)
	if !zero {
		copy(payload[8:], []byte("unique-req12"))
	}
	return payload
}

func TestOrdinarySTUNAndOneZeroRequestDoNotEmit(t *testing.T) {
	detector := NewPacketDetector()
	for index, peer := range []string{"203.0.113.3", "203.0.113.1", "203.0.113.2"} {
		packet := udpFixture(t, packetTime.Add(time.Duration(index)*time.Second), "192.0.2.10", peer, 45678, 19302, stunFixture(false))
		if got := detector.ObservePacket(packet); len(got) != 0 {
			t.Fatalf("normal STUN emitted %+v", got)
		}
	}
	zero := udpFixture(t, packetTime.Add(4*time.Second), "192.0.2.10", "203.0.113.1", 45678, 3478, stunFixture(true))
	if got := detector.ObservePacket(zero); len(got) != 0 {
		t.Fatalf("isolated zero-ID request emitted %+v", got)
	}
	response := stunFixture(true)
	binary.BigEndian.PutUint16(response[:2], 0x0101)
	for _, peer := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if got := detector.ObservePacket(udpFixture(t, packetTime.Add(5*time.Second), "192.0.2.10", peer, 45678, 3478, response)); len(got) != 0 {
			t.Fatalf("echoed zero-ID response emitted %+v", got)
		}
	}
}

func TestSTUNFanoutDistinctPeersAndCooldown(t *testing.T) {
	detector := NewPacketDetector()
	for _, port := range []uint16{3478, 19302} {
		if got := detector.ObservePacket(udpFixture(t, packetTime, "192.0.2.10", "203.0.113.1", 45000, port, stunFixture(true))); len(got) != 0 {
			t.Fatal("two ports at one peer counted as fan-out")
		}
	}
	if got := detector.ObservePacket(udpFixture(t, packetTime.Add(time.Second), "192.0.2.10", "203.0.113.2", 45000, 3478, stunFixture(true))); len(got) != 0 {
		t.Fatal("two distinct peers counted as fan-out")
	}
	got := detector.ObservePacket(udpFixture(t, packetTime.Add(2*time.Second), "192.0.2.10", "203.0.113.3", 45000, 3478, stunFixture(true)))
	if len(got) != 1 || got[0].Kind != "stun_fanout" || got[0].SubjectIP != "192.0.2.10" || len(got[0].Packets) != 3 {
		t.Fatalf("unexpected fan-out evidence: %+v", got)
	}
	for _, packet := range got[0].Packets {
		if len(packet.PayloadHex) != 40 || packet.PayloadLength != 20 {
			t.Fatalf("STUN evidence should retain only header: %+v", packet)
		}
	}
	for index := 3; index < 50; index++ {
		if result := detector.ObservePacket(udpFixture(t, packetTime.Add(time.Duration(index)*time.Second), "192.0.2.10", "203.0.113.3", 45000, 3478, stunFixture(true))); len(result) != 0 {
			t.Fatalf("cooldown emitted duplicate at %ds", index)
		}
	}
	encoded, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	var retried Observation
	if err := json.Unmarshal(encoded, &retried); err != nil || retried.ObservationID != got[0].ObservationID {
		t.Fatal("serialization changed retry identity")
	}
}

func TestSTUNWindowBoundaryAndOutOfOrder(t *testing.T) {
	for _, delta := range []time.Duration{0, time.Nanosecond} {
		detector := NewPacketDetector()
		for index, offset := range []time.Duration{0, 30 * time.Second, 60*time.Second + delta} {
			got := detector.ObservePacket(udpFixture(t, packetTime.Add(offset), "192.0.2.10", fmt.Sprintf("203.0.113.%d", index+1), 45000, 3478, stunFixture(true)))
			if index == 2 && (len(got) == 1) != (delta == 0) {
				t.Fatalf("60-second boundary delta=%v emitted=%d", delta, len(got))
			}
		}
		if got := detector.ObservePacket(udpFixture(t, packetTime.Add(-time.Second), "192.0.2.10", "203.0.113.4", 45000, 3478, stunFixture(true))); len(got) != 0 {
			t.Fatal("stale out-of-order packet emitted evidence")
		}
	}
}

func TestRegistrationNeedsExactSocketAndRecognizableToken(t *testing.T) {
	cases := []struct {
		name, src, peer string
		sport, dport    uint16
		payload         []byte
		offset          time.Duration
		want            bool
	}{
		{"known tag", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("realtek.selfrep\x0045000,45001"), time.Second, true},
		{"other tag", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("selfrep.router,45000"), time.Second, true},
		{"wrong socket", "192.0.2.10", "203.0.113.1", 45001, 3478, []byte("realtek.selfrep"), time.Second, false},
		{"wrong peer", "192.0.2.10", "203.0.113.2", 45000, 3478, []byte("realtek.selfrep"), time.Second, false},
		{"wrong destination port", "192.0.2.10", "203.0.113.1", 45000, 19302, []byte("realtek.selfrep"), time.Second, false},
		{"wrong subject", "192.0.2.11", "203.0.113.1", 45000, 3478, []byte("realtek.selfrep"), time.Second, false},
		{"unknown tag", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("unknown,45000"), time.Second, false},
		{"suffix", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("realtek.selfrep.example"), time.Second, false},
		{"substring", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("notrealtek.selfrep"), time.Second, false},
		{"too old", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("realtek.selfrep"), CorrelationWindow + time.Nanosecond, false},
		{"exact boundary", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("realtek.selfrep"), CorrelationWindow, true},
		{"before request", "192.0.2.10", "203.0.113.1", 45000, 3478, []byte("realtek.selfrep"), -time.Nanosecond, false},
		{"beyond captured prefix", "192.0.2.10", "203.0.113.1", 45000, 3478, append(bytes.Repeat([]byte{0}, 128), []byte("realtek.selfrep")...), time.Second, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewPacketDetector()
			detector.ObservePacket(udpFixture(t, packetTime, "192.0.2.10", "203.0.113.1", 45000, 3478, stunFixture(true)))
			got := detector.ObservePacket(udpFixture(t, packetTime.Add(tt.offset), tt.src, tt.peer, tt.sport, tt.dport, tt.payload))
			if (len(got) == 1) != tt.want {
				t.Fatalf("got %+v; want emission=%v", got, tt.want)
			}
			if tt.want && (got[0].Kind != "cling_registration" || len(got[0].Packets) != 2) {
				t.Fatalf("incorrect correlation evidence: %+v", got)
			}
		})
	}
}

func TestRegistrationInValidSTUNAttributeIsNotARegistration(t *testing.T) {
	detector := NewPacketDetector()
	detector.ObservePacket(udpFixture(t, packetTime, "192.0.2.10", "203.0.113.1", 45000, 3478, stunFixture(true)))
	payload := stunFixture(false)
	value := []byte("realtek.selfrep")
	attribute := append([]byte{0, 6, 0, byte(len(value))}, value...)
	for len(attribute)%4 != 0 {
		attribute = append(attribute, 0)
	}
	payload = append(payload, attribute...)
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)-20))
	if !validSTUNEnvelope(payload) {
		t.Fatal("fixture should be structurally valid STUN")
	}
	if got := detector.ObservePacket(udpFixture(t, packetTime.Add(time.Second), "192.0.2.10", "203.0.113.1", 45000, 3478, payload)); len(got) != 0 {
		t.Fatalf("ordinary STUN attribute treated as registration: %+v", got)
	}
}

func TestRealtekRetainsPrefixOnlyAndDestSubject(t *testing.T) {
	detector := NewPacketDetector()
	payload := []byte("orf;synthetic sensitive command text")
	got := detector.ObservePacket(udpFixture(t, packetTime, "203.0.113.10", "192.0.2.10", 45678, 9034, payload))
	if len(got) != 1 || got[0].SubjectIP != "192.0.2.10" || got[0].Kind != "realtek_exploit" {
		t.Fatalf("unexpected exploit evidence: %+v", got)
	}
	if got[0].Packets[0].PayloadHex != "6f72663b" || got[0].Packets[0].PayloadLength != len(payload) {
		t.Fatal("exploit evidence retained more than the prefix or lost original length")
	}
	if duplicate := detector.ObservePacket(udpFixture(t, packetTime.Add(time.Second), "203.0.113.11", "192.0.2.10", 45679, 9034, payload)); len(duplicate) != 0 {
		t.Fatal("target cooldown did not aggregate repeated attempts")
	}
	next := detector.ObservePacket(udpFixture(t, packetTime.Add(CorrelationWindow), "203.0.113.11", "192.0.2.10", 45679, 9034, payload))
	if len(next) != 1 || next[0].ObservationID == got[0].ObservationID {
		t.Fatal("a new occurrence needs a new random identity after cooldown")
	}
	for _, invalid := range [][]byte{[]byte("orf;"), []byte("orf; \n"), []byte("orf status"), []byte("prefix orf;id")} {
		if result := NewPacketDetector().ObservePacket(udpFixture(t, packetTime, "203.0.113.10", "192.0.2.10", 45678, 9034, invalid)); len(result) != 0 {
			t.Fatalf("non-command packet emitted: %q", invalid)
		}
	}
}

func TestPacketRejectsFragmentsTruncationAndMalformedLengths(t *testing.T) {
	base := udpFixture(t, packetTime, "192.0.2.10", "203.0.113.1", 45000, 3478, stunFixture(true))
	tests := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"IPv4 more fragments", func(data []byte) []byte { data[6] |= 0x20; return data }},
		{"IPv4 fragment offset", func(data []byte) []byte { data[7] = 1; return data }},
		{"UDP short declared length", func(data []byte) []byte { binary.BigEndian.PutUint16(data[24:26], 27); return data }},
		{"UDP long declared length", func(data []byte) []byte { binary.BigEndian.PutUint16(data[24:26], 29); return data }},
		{"truncated bytes", func(data []byte) []byte { return data[:len(data)-1] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.edit(append([]byte(nil), base.Data()...))
			packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
			packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: packetTime, CaptureLength: len(data), Length: len(base.Data())}
			if _, _, ok := packetEvidence(packet); ok {
				t.Fatal("malformed packet accepted")
			}
		})
	}
	base.Metadata().Truncated = true
	if _, _, ok := packetEvidence(base); ok {
		t.Fatal("capture truncation flag was ignored")
	}
	for _, payload := range [][]byte{
		{}, {0, 1}, append(stunFixture(true), 0),
		append(stunFixture(true), 0, 6, 0, 9),
	} {
		if zeroIDBindingRequest(payload) {
			t.Fatalf("malformed STUN accepted: %x", payload)
		}
	}
	badAttribute := append(stunFixture(true), 0, 6, 0, 9)
	binary.BigEndian.PutUint16(badAttribute[2:4], 4)
	if zeroIDBindingRequest(badAttribute) {
		t.Fatal("out-of-bounds STUN attribute accepted")
	}
}

func TestDetectorStateAndPrefixBounds(t *testing.T) {
	detector := NewPacketDetector()
	for index := 0; index < 400; index++ {
		src := fmt.Sprintf("2001:db8::%x", index+1)
		detector.ObservePacket(udpFixture(t, packetTime, src, "2001:db8:1::1", 45000, 3478, stunFixture(true)))
	}
	if len(detector.subjects) != maxTrackedSubjects {
		t.Fatalf("subject map size=%d", len(detector.subjects))
	}
	for index := 1; index < 200; index++ {
		detector.ObservePacket(udpFixture(t, packetTime.Add(time.Second), "192.0.2.10", fmt.Sprintf("203.0.113.%d", index), 45000, 3478, stunFixture(true)))
	}
	if got := len(detector.subjects["192.0.2.10"].requests); got != maxFlowsPerSubject {
		t.Fatalf("flow map size=%d", got)
	}
	detector = NewPacketDetector()
	detector.ObservePacket(udpFixture(t, packetTime, "192.0.2.10", "203.0.113.1", 45000, 3478, stunFixture(true)))
	payload := append([]byte("realtek.selfrep\x00"), bytes.Repeat([]byte{'0'}, 512)...)
	got := detector.ObservePacket(udpFixture(t, packetTime.Add(time.Second), "192.0.2.10", "203.0.113.1", 45000, 3478, payload))
	if len(got) != 1 {
		t.Fatal("expected correlated bounded registration")
	}
	prefix, _ := hex.DecodeString(got[0].Packets[1].PayloadHex)
	if len(prefix) != maxPacketPrefix || got[0].Packets[1].PayloadLength != len(payload) {
		t.Fatal("registration prefix was not bounded")
	}
	detector.ObservePacket(udpFixture(t, packetTime.Add(2*CorrelationWindow), "192.0.2.11", "203.0.113.1", 45000, 3478, stunFixture(true)))
	if len(detector.subjects) != 1 {
		t.Fatal("expired state retained")
	}
}

func TestDetectorConcurrentObserversPreserveCooldown(t *testing.T) {
	detector := NewPacketDetector()
	packet := udpFixture(t, packetTime, "203.0.113.10", "192.0.2.10", 45000, 9034, []byte("orf;synthetic"))
	var workers sync.WaitGroup
	results := make(chan Observation, 32)
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for _, observation := range detector.ObservePacket(packet) {
				results <- observation
			}
		}()
	}
	workers.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("concurrent cooldown emitted %d observations", len(results))
	}
}
