package passive

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/vedetta-network/vedetta/sensor/internal/netscan"
)

// Synthetic values only (constitution): RFC 5737 IPs (192.0.2.x / 198.51.100.x),
// 00:00:5E:00:53:xx MACs, .local placeholder names.

// findHostByIP returns the parsed host with the given IP, or nil.
func findHostByIP(hosts []netscan.DiscoveredHost, ip string) *netscan.DiscoveredHost {
	for i := range hosts {
		if hosts[i].IPAddress == ip {
			return &hosts[i]
		}
	}
	return nil
}

func hasService(host *netscan.DiscoveredHost, svc string) bool {
	if host == nil {
		return false
	}
	for _, s := range host.Services {
		if s == svc {
			return true
		}
	}
	return false
}

// txtRecord builds a TXT resource record with the given owner name and key=value pairs.
func txtRecord(name string, pairs ...string) layers.DNSResourceRecord {
	txts := make([][]byte, 0, len(pairs))
	for _, p := range pairs {
		txts = append(txts, []byte(p))
	}
	return layers.DNSResourceRecord{
		Name:  []byte(name),
		Type:  layers.DNSTypeTXT,
		Class: layers.DNSClassIN,
		TXTs:  txts,
	}
}

func srvRecord(name, target string, port uint16) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:  []byte(name),
		Type:  layers.DNSTypeSRV,
		Class: layers.DNSClassIN,
		SRV: layers.DNSSRV{
			Priority: 0,
			Weight:   0,
			Port:     port,
			Name:     []byte(target),
		},
	}
}

func ptrRecord(name, target string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:  []byte(name),
		Type:  layers.DNSTypePTR,
		Class: layers.DNSClassIN,
		PTR:   []byte(target),
	}
}

func aRecord(name, ip string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:  []byte(name),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		IP:    net.ParseIP(ip).To4(),
	}
}

// TestMDNSPTRServiceEmitted documents defect (a): the PTR service-extraction
// branch is dead code. trimDNSName strips names beginning with '_' to "", so the
// subsequent HasPrefix(svc, "_") check can never be true and passive PTR service
// discovery has never emitted a service. A PTR/SRV/A chain for a single device
// MUST yield the service type attached to that device's host.
func TestMDNSPTRServiceEmitted(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			ptrRecord("_googlecast._tcp.local", "Living Room TV._googlecast._tcp.local"),
			srvRecord("Living Room TV._googlecast._tcp.local", "chromecast-1.local", 8009),
			aRecord("chromecast-1.local", "192.0.2.57"),
		},
	}

	hosts := hostsFromMDNS(dns, "192.0.2.57")

	host := findHostByIP(hosts, "192.0.2.57")
	if host == nil {
		t.Fatalf("expected a host for 192.0.2.57, got hosts=%+v", hosts)
	}
	if !hasService(host, "_googlecast._tcp") {
		t.Fatalf("expected service _googlecast._tcp on host, got services=%v", host.Services)
	}
}

// TestMDNSMetadataAttachesToCorrectHost documents defect (b): TXT/PTR metadata
// attaches to hosts[len(hosts)-1], mislabeling hosts in multi-host packets.
// Here a single packet carries records for TWO distinct devices. The model from
// each TXT record MUST land on the device it describes, not on "the last A host".
func TestMDNSMetadataAttachesToCorrectHost(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			// Device 1: a camera.
			srvRecord("Front Door._camera._tcp.local", "camera-a.local", 443),
			txtRecord("Front Door._camera._tcp.local", "md=SynthCam 100"),
			aRecord("camera-a.local", "192.0.2.11"),
			// Device 2: a TV. It is the LAST A record, so the buggy code would
			// attach the camera's model to it (or vice versa).
			srvRecord("Living Room TV._googlecast._tcp.local", "tv-b.local", 8009),
			txtRecord("Living Room TV._googlecast._tcp.local", "md=SynthTV 200"),
			aRecord("tv-b.local", "192.0.2.22"),
		},
	}

	hosts := hostsFromMDNS(dns, "192.0.2.11")

	cam := findHostByIP(hosts, "192.0.2.11")
	tv := findHostByIP(hosts, "192.0.2.22")
	if cam == nil || tv == nil {
		t.Fatalf("expected both hosts, got %+v", hosts)
	}
	if cam.Model != "SynthCam 100" {
		t.Fatalf("camera model mislabeled: got %q want %q", cam.Model, "SynthCam 100")
	}
	if tv.Model != "SynthTV 200" {
		t.Fatalf("tv model mislabeled: got %q want %q", tv.Model, "SynthTV 200")
	}
}

// TestMDNSFriendlyNameFromInstanceLabel: the friendly name is derived from the
// mDNS service-instance label when no TXT fn=/n= is present.
func TestMDNSFriendlyNameFromInstanceLabel(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			ptrRecord("_googlecast._tcp.local", "Living Room TV._googlecast._tcp.local"),
			srvRecord("Living Room TV._googlecast._tcp.local", "chromecast-1.local", 8009),
			aRecord("chromecast-1.local", "192.0.2.57"),
		},
	}
	host := findHostByIP(hostsFromMDNS(dns, "192.0.2.57"), "192.0.2.57")
	if host == nil {
		t.Fatal("expected host")
	}
	if host.FriendlyName != "Living Room TV" {
		t.Fatalf("friendly name from instance label: got %q want %q", host.FriendlyName, "Living Room TV")
	}
}

// TestMDNSFriendlyNameFromTXT: an explicit TXT fn= overrides the instance label.
func TestMDNSFriendlyNameFromTXT(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			srvRecord("Chromecast-abc._googlecast._tcp.local", "chromecast-2.local", 8009),
			txtRecord("Chromecast-abc._googlecast._tcp.local", "fn=Kitchen Display", "md=Chromecast Ultra"),
			aRecord("chromecast-2.local", "192.0.2.58"),
		},
	}
	host := findHostByIP(hostsFromMDNS(dns, "192.0.2.58"), "192.0.2.58")
	if host == nil {
		t.Fatal("expected host")
	}
	if host.FriendlyName != "Kitchen Display" {
		t.Fatalf("friendly name from TXT fn=: got %q want %q", host.FriendlyName, "Kitchen Display")
	}
	if host.Model != "Chromecast Ultra" {
		t.Fatalf("model with space preserved: got %q want %q", host.Model, "Chromecast Ultra")
	}
}

// TestMDNSFriendlyNameEscaped: DNS-SD escapes spaces/dots in instance labels.
func TestMDNSFriendlyNameEscaped(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			srvRecord(`Alice\032Office\032Printer._ipp._tcp.local`, "printer-x.local", 631),
			aRecord("printer-x.local", "192.0.2.61"),
		},
	}
	host := findHostByIP(hostsFromMDNS(dns, "192.0.2.61"), "192.0.2.61")
	if host == nil {
		t.Fatal("expected host")
	}
	if host.FriendlyName != "Alice Office Printer" {
		t.Fatalf("escaped instance label: got %q want %q", host.FriendlyName, "Alice Office Printer")
	}
}

// TestMDNSFriendlyNameAbsent: a plain A record with no service instance yields
// no friendly name (not a crash, not the hostname).
func TestMDNSFriendlyNameAbsent(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			aRecord("plainhost.local", "192.0.2.62"),
		},
	}
	host := findHostByIP(hostsFromMDNS(dns, "192.0.2.62"), "192.0.2.62")
	if host == nil {
		t.Fatal("expected host")
	}
	if host.FriendlyName != "" {
		t.Fatalf("expected no friendly name, got %q", host.FriendlyName)
	}
}

// TestSSDPFriendlyName: a friendly-name header is surfaced without any active
// LOCATION XML fetch.
func TestSSDPFriendlyName(t *testing.T) {
	payload := []byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
		"SERVER: SynthOS/1.0 UPnP/1.1\r\nFRIENDLYNAME.SMARTSPEAKER: Office Speaker\r\n\r\n")
	host := hostFromSSDPPayload(payload, "192.0.2.71")
	if host == nil {
		t.Fatal("expected SSDP host")
	}
	if host.FriendlyName != "Office Speaker" {
		t.Fatalf("SSDP friendly name: got %q want %q", host.FriendlyName, "Office Speaker")
	}
}

// --- T1.4: malformed / hostile input hardening (must not panic, degrade
// gracefully). ---

// TestMDNSMalformedEmptyNames: empty/blank owner names must not attach metadata
// or crash.
func TestMDNSMalformedEmptyNames(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			ptrRecord("", ""),
			srvRecord("", "", 0),
			txtRecord("", "md=Ghost"),
			aRecord("", "192.0.2.80"),
		},
	}
	hosts := hostsFromMDNS(dns, "192.0.2.80")
	// A record with an empty owner name is keyed by IP and surfaced, but no
	// metadata can attach (no resolvable SRV target).
	for _, h := range hosts {
		if h.Model == "Ghost" {
			t.Fatalf("metadata leaked onto host with empty owner name: %+v", h)
		}
	}
}

// TestMDNSMalformedPTRWithoutSRVorA: PTR/instance with no SRV target and no A
// record — the instance is unresolved and its service must not attach anywhere.
func TestMDNSMalformedPTRWithoutSRVorA(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			ptrRecord("_http._tcp.local", "Orphan._http._tcp.local"),
			txtRecord("Orphan._http._tcp.local", "md=NoHome"),
			// An unrelated host in the same packet — must NOT absorb the orphan's data.
			aRecord("other.local", "192.0.2.81"),
		},
	}
	hosts := hostsFromMDNS(dns, "192.0.2.81")
	other := findHostByIP(hosts, "192.0.2.81")
	if other == nil {
		t.Fatal("expected unrelated host")
	}
	if other.Model == "NoHome" || hasService(other, "_http._tcp") {
		t.Fatalf("orphan instance data leaked onto unrelated host: %+v", other)
	}
}

// TestMDNSMalformedTXTBeforeA: record ordering must not matter — TXT/SRV before
// the A record still resolves correctly (graph is order-independent).
func TestMDNSMalformedTXTBeforeA(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			txtRecord("Cam._camera._tcp.local", "md=SynthCam 100"),
			srvRecord("Cam._camera._tcp.local", "cam.local", 443),
			aRecord("cam.local", "192.0.2.82"),
		},
	}
	host := findHostByIP(hostsFromMDNS(dns, "192.0.2.82"), "192.0.2.82")
	if host == nil {
		t.Fatal("expected host")
	}
	if host.Model != "SynthCam 100" {
		t.Fatalf("TXT-before-A ordering: got model %q want %q", host.Model, "SynthCam 100")
	}
}

// TestMDNSNoARecordFallbackFriendlyNameDeterministic documents the LOW finding:
// in the no-A fallback the friendly_name was picked via `range instances` (Go
// map iteration, randomized), so the SAME packet yielded different labels
// run-to-run. Two service instances (Alpha, Bravo) with no A/AAAA record must
// resolve to a single, STABLE friendly name across many runs. Alpha is inserted
// first, so insertion-order iteration must always pick "Alpha".
func TestMDNSNoARecordFallbackFriendlyNameDeterministic(t *testing.T) {
	build := func() *layers.DNS {
		return &layers.DNS{
			QR: true,
			Answers: []layers.DNSResourceRecord{
				// No A/AAAA record anywhere -> fallback path. Two distinct
				// instances, each contributing a friendly label.
				srvRecord("Alpha._x._tcp.local", "alpha-host.local", 1),
				srvRecord("Bravo._y._tcp.local", "bravo-host.local", 2),
			},
		}
	}
	want := ""
	for run := 0; run < 50; run++ {
		hosts := hostsFromMDNS(build(), "192.0.2.90")
		host := findHostByIP(hosts, "192.0.2.90")
		if host == nil {
			t.Fatalf("run %d: expected fallback host for 192.0.2.90, got %+v", run, hosts)
		}
		if host.FriendlyName == "" {
			t.Fatalf("run %d: expected a friendly name, got empty", run)
		}
		if run == 0 {
			want = host.FriendlyName
			if want != "Alpha" {
				t.Fatalf("expected first-inserted instance label %q, got %q", "Alpha", want)
			}
			continue
		}
		if host.FriendlyName != want {
			t.Fatalf("run %d: non-deterministic friendly name: got %q want %q", run, host.FriendlyName, want)
		}
	}
}

// TestMDNSNoARecordFallbackHostnameNotInstance documents the LOW finding: in the
// no-A fallback the Hostname could become a service-INSTANCE name. For a packet
// whose first answer is an SRV record, the owner is "Inst._x._tcp.local" — an
// instance string that trimDNSName does not reject — and it leaked into
// Hostname, feeding Core's identity resolver garbage. The fallback host's
// Hostname must NOT contain a "._" service label.
func TestMDNSNoARecordFallbackHostnameNotInstance(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			// First answer is an SRV whose owner is a service-instance name.
			srvRecord("Inst._x._tcp.local", "target-host.local", 1),
			txtRecord("Inst._x._tcp.local", "md=SynthThing"),
		},
	}
	host := findHostByIP(hostsFromMDNS(dns, "192.0.2.91"), "192.0.2.91")
	if host == nil {
		t.Fatalf("expected fallback host for 192.0.2.91")
	}
	if strings.Contains(host.Hostname, "._") {
		t.Fatalf("fallback Hostname is a service-instance name, not a hostname: %q", host.Hostname)
	}
}

// TestMDNSMalformedFlood: a packet with more records than the caps must not
// panic and must stay bounded — specifically the per-host service cap
// (maxServicesHost) must be enforced.
//
// The A record ("flood.local") is placed FIRST so it survives the
// maxMDNSRecords=128 truncation and a graph host actually surfaces. It is
// followed by an SRV binding the instance to that host, then far more than
// maxServicesHost DISTINCT service-type PTRs all pointing at the same instance,
// so the resolved host's Services list is genuinely driven past the cap. Without
// the cap, len(h.Services) would exceed maxServicesHost.
func TestMDNSMalformedFlood(t *testing.T) {
	answers := []layers.DNSResourceRecord{
		// First (and within the first 128 records): the A record + SRV so the
		// host surfaces and the instance resolves to it.
		aRecord("flood.local", "192.0.2.83"),
		srvRecord("Inst._svc0._tcp.local", "flood.local", 1),
	}
	// Many DISTINCT service-type PTRs, all pointing at the same instance, to
	// drive the resolved host's Services list well past maxServicesHost.
	for i := 0; i < maxServicesHost*8; i++ {
		svcType := fmt.Sprintf("_svc%d._tcp.local", i)
		answers = append(answers, ptrRecord(svcType, "Inst._svc0._tcp.local"))
	}
	dns := &layers.DNS{QR: true, Answers: answers}

	hosts := hostsFromMDNS(dns, "192.0.2.83") // must not panic

	// The graph host for the A owner MUST surface (proves the A record was not
	// truncated away and the test is exercising a real host, not 0 services).
	host := findHostByIP(hosts, "192.0.2.83")
	if host == nil {
		t.Fatalf("expected graph host for 192.0.2.83, got hosts=%+v", hosts)
	}
	// The cap must hold on the surfaced host and every other host.
	for _, h := range hosts {
		if len(h.Services) > maxServicesHost {
			t.Fatalf("service cap exceeded: %d > %d", len(h.Services), maxServicesHost)
		}
	}
}
