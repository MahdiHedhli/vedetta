package netscan

import (
	"reflect"
	"testing"
)

func TestCorroborateLiveNeighborsRequiresExactScopedUnambiguousRows(t *testing.T) {
	target, err := parseIPv4Scope("192.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	link := localScope{iface: "lan0", ifIndex: 7, network: mustTestNetwork(t, "192.0.2.0/24")}
	rows := []neighbor{
		// Safe exact live mapping (identical duplicate is harmless).
		{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 7, state: neighborStateDynamic},
		// Conflicting MACs for one live IP: withhold.
		{ip: "192.0.2.11", mac: "00:00:5e:00:53:11", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.11", mac: "00:00:5e:00:53:12", ifIndex: 7, state: neighborStateDynamic},
		// Proxy ARP: same MAC answers a live and unrelated scoped IP. Withhold.
		{ip: "192.0.2.12", mac: "00:00:5e:00:53:20", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.200", mac: "00:00:5e:00:53:20", ifIndex: 7, state: neighborStateDynamic},
		// Wrong interface, off-link, and static evidence are never candidates.
		{ip: "192.0.2.13", mac: "00:00:5e:00:53:13", ifIndex: 8, state: neighborStateDynamic},
		{ip: "192.0.3.14", mac: "00:00:5e:00:53:14", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.15", mac: "00:00:5e:00:53:15", ifIndex: 7, state: neighborStateStatic},
	}
	live := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.3.14", "192.0.2.15"}
	want := map[string]string{"192.0.2.10": "00:00:5e:00:53:10"}
	if got := corroborateLiveNeighbors(live, rows, target, link); !reflect.DeepEqual(got, want) {
		t.Fatalf("corroboration = %#v, want %#v", got, want)
	}
}

func TestCorroborateLiveNeighborsRequiresResolvedInterfaceIndex(t *testing.T) {
	target, _ := parseIPv4Scope("192.0.2.0/24")
	rows := []neighbor{{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 7, state: neighborStateDynamic}}
	link := localScope{iface: "lan0", network: mustTestNetwork(t, "192.0.2.0/24")}
	if got := corroborateLiveNeighbors([]string{"192.0.2.10"}, rows, target, link); len(got) != 0 {
		t.Fatalf("unindexed link produced identity evidence: %#v", got)
	}
}

func TestCorroborateLiveNeighborsSingleIPSeesProxyMACElsewhereOnLink(t *testing.T) {
	target, err := parseIPv4Scope("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	link := localScope{iface: "lan0", ifIndex: 7, network: mustTestNetwork(t, "192.0.2.0/24")}
	proxyMAC := "00:00:5e:00:53:50"
	rows := []neighbor{
		{ip: "192.0.2.10", mac: proxyMAC, ifIndex: 7, state: neighborStateDynamic},
		// Outside the single-IP target but on the same selected link. This must
		// still veto MAC attribution for the live target.
		{ip: "192.0.2.200", mac: proxyMAC, ifIndex: 7, state: neighborStateDynamic},
		// Static and wrong-interface reuse do not describe this link's dynamic
		// neighbor identity and must not affect the result.
		{ip: "192.0.2.201", mac: "00:00:5e:00:53:51", ifIndex: 7, state: neighborStateStatic},
		{ip: "192.0.2.202", mac: "00:00:5e:00:53:52", ifIndex: 8, state: neighborStateDynamic},
	}
	if got := corroborateLiveNeighbors([]string{"192.0.2.10"}, rows, target, link); len(got) != 0 {
		t.Fatalf("single-IP target promoted a link-wide proxy MAC: %#v", got)
	}
}

func TestCorroborateLiveNeighborsStaticRowsParticipateOnlyInAmbiguity(t *testing.T) {
	target, err := parseIPv4Scope("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	link := localScope{iface: "lan0", ifIndex: 7, network: mustTestNetwork(t, "192.0.2.0/24")}
	rows := []neighbor{
		// Identical static configuration is harmless but does not itself promote.
		{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.10", mac: "00:00:5e:00:53:10", ifIndex: 7, state: neighborStateStatic},
		// A conflicting static mapping for the same live IP vetoes the dynamic row.
		{ip: "192.0.2.11", mac: "00:00:5e:00:53:11", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.11", mac: "00:00:5e:00:53:12", ifIndex: 7, state: neighborStateStatic},
		// Static reuse elsewhere on-link makes the dynamic MAC proxy-like.
		{ip: "192.0.2.13", mac: "00:00:5e:00:53:13", ifIndex: 7, state: neighborStateDynamic},
		{ip: "192.0.2.200", mac: "00:00:5e:00:53:13", ifIndex: 7, state: neighborStateStatic},
		// Static-only rows remain ineligible even when the IP replied.
		{ip: "192.0.2.14", mac: "00:00:5e:00:53:14", ifIndex: 7, state: neighborStateStatic},
	}
	want := map[string]string{"192.0.2.10": "00:00:5e:00:53:10"}
	got := corroborateLiveNeighbors([]string{"192.0.2.10", "192.0.2.11", "192.0.2.13", "192.0.2.14"}, rows, target, link)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("static-aware corroboration = %#v, want %#v", got, want)
	}
}

func TestCorroborateLiveNeighborsSeesProxyMACAcrossPrefixesOnSelectedInterface(t *testing.T) {
	target, err := parseIPv4Scope("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	link := localScope{iface: "lan0", ifIndex: 7, network: mustTestNetwork(t, "192.0.2.0/24")}
	proxyMAC := "00:00:5e:00:53:70"
	rows := []neighbor{
		{ip: "192.0.2.10", mac: proxyMAC, ifIndex: 7, state: neighborStateDynamic},
		// A second prefix on the same L2 interface still participates in the
		// link-wide proxy check even though it is outside link.network.
		{ip: "198.51.100.20", mac: proxyMAC, ifIndex: 7, state: neighborStateStatic},
	}
	if got := corroborateLiveNeighbors([]string{"192.0.2.10"}, rows, target, link); len(got) != 0 {
		t.Fatalf("cross-prefix proxy MAC was promoted: %#v", got)
	}
}
