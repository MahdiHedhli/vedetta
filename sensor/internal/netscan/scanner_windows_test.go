//go:build windows

package netscan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWindowsScannerRejectsNumericRangeBeforeTopologyOrSweep(t *testing.T) {
	scanner := testWindowsScanner(t)
	scanner.detectSubnets = func() ([]DetectedSubnet, error) {
		t.Fatal("topology resolution ran for an unsupported Windows range target")
		return nil, nil
	}
	scanner.sweepBound = func(context.Context, []string, string) ([]string, error) {
		t.Fatal("ICMP sweep ran for an unsupported Windows range target")
		return nil, nil
	}

	_, err := scanner.ScanContext(context.Background(), "192.0.2.1-20", false)
	if err == nil || !strings.Contains(err.Error(), "unsupported by the source-bound Windows scanner") {
		t.Fatalf("numeric range error = %v, want explicit source-bound Windows rejection", err)
	}
}

func testWindowsScanner(t *testing.T) *Scanner {
	t.Helper()
	return &Scanner{
		BinaryPath: "native",
		detectSubnets: func() ([]DetectedSubnet, error) {
			return []DetectedSubnet{{Interface: "Ethernet", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
		},
		interfaceIndex: func(name string) (int, error) {
			if name != "Ethernet" {
				return 0, errors.New("missing interface")
			}
			return 17, nil
		},
		sweepBound: func(ctx context.Context, hosts []string, source string) ([]string, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if source != "192.0.2.200" {
				t.Fatalf("ICMP source = %q, want resolved link address", source)
			}
			return []string{"192.0.2.10", "192.0.2.11"}, nil
		},
	}
}

func TestWindowsScannerCancellationStopsGenerationBeforeNeighborRead(t *testing.T) {
	scanner := testWindowsScanner(t)
	scanner.ConfigureNativeDiscovery("Ethernet", true)
	started := make(chan struct{})
	scanner.sweepBound = func(ctx context.Context, _ []string, _ string) ([]string, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	scanner.readNeighbors = func() ([]neighbor, error) {
		t.Fatal("neighbor table read after scan cancellation")
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := scanner.ScanContext(ctx, "192.0.2.0/24", false)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ScanContext cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("native scan did not stop after cancellation")
	}
}

func TestWindowsScannerUsesBoundLivenessAndSameGenerationNeighborEvidence(t *testing.T) {
	scanner := testWindowsScanner(t)
	scanner.ConfigureNativeDiscovery("Ethernet", true)
	scanner.readNeighbors = func() ([]neighbor, error) {
		return []neighbor{
			{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 17, state: neighborStateDynamic},
			// One MAC on multiple IPs is proxy-ARP-like and must stay IP-only.
			{ip: "192.0.2.11", mac: "00:00:5e:00:53:20", ifIndex: 17, state: neighborStateDynamic},
			{ip: "192.0.2.12", mac: "00:00:5e:00:53:20", ifIndex: 17, state: neighborStateDynamic},
		}, nil
	}
	result, err := scanner.Scan("192.0.2.0/24", false)
	if err != nil {
		t.Fatal(err)
	}
	want := []DiscoveredHost{
		{IPAddress: "192.0.2.10", MACAddress: "00:00:5e:00:53:10", Status: "up", DiscoverySource: "native_icmp_arp", ObservedAt: result.ScanTime},
		{IPAddress: "192.0.2.11", Status: "up", DiscoverySource: "native_icmp_bound", ObservedAt: result.ScanTime},
	}
	if !reflect.DeepEqual(result.Hosts, want) {
		t.Fatalf("hosts = %+v, want %+v", result.Hosts, want)
	}
}

func TestWindowsScannerARPDiscoveryDisabledNeverReadsOrAttachesMAC(t *testing.T) {
	scanner := testWindowsScanner(t)
	scanner.ConfigureNativeDiscovery("Ethernet", false)
	scanner.readNeighbors = func() ([]neighbor, error) {
		t.Fatal("neighbor table read despite --arp-discovery=false")
		return nil, nil
	}
	result, err := scanner.Scan("192.0.2.0/24", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range result.Hosts {
		if host.MACAddress != "" || host.DiscoverySource != "native_icmp_bound" {
			t.Fatalf("disabled ARP enrichment leaked cache identity: %+v", host)
		}
	}
}

func TestWindowsScannerFailsClosedWhenLinkChangesDuringSweep(t *testing.T) {
	scanner := testWindowsScanner(t)
	calls := 0
	scanner.detectSubnets = func() ([]DetectedSubnet, error) {
		calls++
		if calls == 1 {
			return []DetectedSubnet{{Interface: "Ethernet", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
		}
		return nil, nil
	}
	if _, err := scanner.Scan("192.0.2.0/24", false); err == nil {
		t.Fatal("disappearing interface returned attributed liveness")
	}
}

func TestWindowsScannerFailsClosedWhenLinkChangesDuringNeighborRead(t *testing.T) {
	scanner := testWindowsScanner(t)
	scanner.ConfigureNativeDiscovery("Ethernet", true)
	calls := 0
	scanner.detectSubnets = func() ([]DetectedSubnet, error) {
		calls++
		if calls <= 2 {
			return []DetectedSubnet{{Interface: "Ethernet", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"}}, nil
		}
		return []DetectedSubnet{{Interface: "Ethernet", IPAddress: "192.0.2.201", CIDR: "192.0.2.0/24"}}, nil
	}
	scanner.readNeighbors = func() ([]neighbor, error) {
		return []neighbor{{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 17, state: neighborStateDynamic}}, nil
	}
	if _, err := scanner.Scan("192.0.2.0/24", false); err == nil || !strings.Contains(err.Error(), "changed during neighbor read") {
		t.Fatalf("post-cache topology change error = %v, want fail-closed neighbor-read attribution", err)
	}
	if calls != 3 {
		t.Fatalf("topology checks = %d, want initial, post-sweep, and post-cache", calls)
	}
}

func TestWindowsScannerHonorsCancellationDuringNeighborRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	scanner := testWindowsScanner(t)
	scanner.ConfigureNativeDiscovery("Ethernet", true)
	scanner.readNeighbors = func() ([]neighbor, error) {
		cancel()
		return []neighbor{{
			ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 17, state: neighborStateDynamic,
		}}, nil
	}
	result, err := scanner.ScanContext(ctx, "192.0.2.0/24", false)
	if !errors.Is(err, context.Canceled) || result != nil {
		t.Fatalf("cancel-during-neighbor-read result=%+v err=%v, want nil/context.Canceled", result, err)
	}
}

func TestWindowsScannerFailsClosedOnAmbiguousLink(t *testing.T) {
	scanner := testWindowsScanner(t)
	scanner.detectSubnets = func() ([]DetectedSubnet, error) {
		return []DetectedSubnet{
			{Interface: "Ethernet", IPAddress: "192.0.2.200", CIDR: "192.0.2.0/24"},
			{Interface: "Wi-Fi", IPAddress: "192.0.2.201", CIDR: "192.0.2.0/24"},
		}, nil
	}
	scanner.interfaceIndex = func(name string) (int, error) {
		if name == "Ethernet" {
			return 17, nil
		}
		return 23, nil
	}
	if _, err := scanner.Scan("192.0.2.0/24", false); err == nil {
		t.Fatal("ambiguous links auto-selected an ICMP source")
	}
}
