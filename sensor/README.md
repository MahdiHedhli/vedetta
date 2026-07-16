# Vedetta Sensor

The Vedetta Sensor is a native host binary that observes a network segment and feeds
device discovery + DNS signals to Vedetta Core. It runs directly on the host OS (not in
a container) because L2 visibility requires the host network stack. See
[docs/sensor-architecture.md](../docs/sensor-architecture.md) for the full architecture.

## Unprivileged ARP-cache discovery

The sensor learns IP↔MAC bindings by reading the operating system's own neighbor (ARP)
cache — the table the kernel already maintains:

| OS            | Source                                   |
|---------------|------------------------------------------|
| Linux (Pi 4)  | `/proc/net/arp`                          |
| macOS / BSD   | routing table via `route.FetchRIB`       |
| Windows       | `GetIpNetTable` via `iphlpapi` (native)  |

Reading the cache is **passive** and is **on by default** (`--arp-discovery`). The reader
accepts only structurally valid, dynamic unicast mappings in the configured CIDR and,
where the OS provides it, the selected interface. Static/permanent entries and neighbors
from unrelated LAN interfaces are not treated as device observations. Known container,
CNI, VPN, WSL, and Hyper-V adapter names are excluded using a conservative name-based
classifier; custom or renamed virtual adapters cannot be identified infallibly, so hosts
with unusual topology should explicitly pin both the intended LAN subnet (`--cidr`) and
interface (`--passive-iface`); interface pinning does not change `--cidr auto` selection.
Private address
ranges are never classified as virtual by themselves, and physical LANs using
172.17-31/16 or 192.168.65/24 remain eligible. If the service starts
before DHCP while an explicit `--cidr` is configured, the reader waits and attaches when
the matching directly connected link appears rather than requiring a service restart.
ARP link selection is resolved from that CIDR; only a valid interface name explicitly
passed with `--passive-iface` pins it. The `auto`/`any` values and an interface chosen
automatically by pcap are never inherited by the ARP source.
New, changed, or reappearing mappings flow through the passive pipeline as
`discovery_source: "arp_cache"`, with status `observed` rather than `up`.

An unchanged cache row is not re-emitted every 30 seconds: OS caches can be stale, and
polling one must not keep a device's `last_seen` or address ownership alive indefinitely.
Core stores cache-only IP/MAC evidence at reduced confidence and refuses to let it
displace a recent stronger DHCP, packet, or active-scan binding. A cache MAC remains
provisional: it cannot merge devices, populate the canonical MAC, or drive OUI/device-risk
fingerprinting until a live source corroborates it. Core also keeps a scoped latest-state
ledger for each cache IP: unique MACs are node-local HMACs in that ledger, while a blank
conflicting/proxy transition remains an explicit ambiguity veto across retries and
out-of-order delivery. Core issues a non-secret process epoch during authenticated
registration and activates it only when the sensor returns it; a local sequence then
preserves cache order when NTP moves wall time backward. Core scopes both fields to the
authenticated sensor. The first accepted `(sensor, segment, IP, epoch, sequence)` payload
is immutable: an exact retry is idempotent, while a changed MAC/state/timestamp is logged
and acknowledged without changing identity. A real cache transition uses the next
sequence. Contradictory rows first received together in one report are pre-collapsed to
ambiguous before persistence. Once a later sequence or process epoch is accepted, older
known deliveries are acknowledged as stale before any provisional or identity projection.
Core retains retired epoch history and bounds only candidates that were never returned.
The delivery fields never leave the local Core through
telemetry. Unsequenced legacy cache rows
remain provisional and cannot drive Core-side MAC fusion. On Windows, each source-bound native
ICMP generation can immediately re-read the same interface's cache for the exact IPs that
replied; an unambiguous IP/MAC is then reported as `native_icmp_arp`. That direct
corroboration does not depend on the background poller's change-only snapshot, so a delayed
Core delivery does not lose the MAC. Proxy-ARP snapshots (one MAC answering for multiple
IPs anywhere on the selected link) are reported without a MAC identity; conflicting
same-IP rows are withheld until the cache converges.

Windows ICMP uses `IcmpSendEcho2Ex` with the resolved link's IPv4 source address. The link
is revalidated after every generation and ambiguity or disappearance fails closed. Bound
IP-only results are marked `native_icmp_bound`; legacy/unbound `native_icmp` evidence is
never eligible for cache-MAC fusion. `--arp-discovery=false` disables both background cache
observations and this direct cache corroboration while retaining source-bound liveness.

### Privilege story

The ARP-cache reader itself needs **no root, raw sockets, `CAP_NET_RAW`, libpcap, or
nmap** to learn device MAC addresses on Linux and macOS — it just reads a
kernel-maintained file or table. **Native-host execution is still required** (a container
cannot see the host's L2 neighbor cache), and the separate passive **DNS/pcap** capture
path still needs elevated privileges where enabled — that is unchanged by this source.

> **Current limitation:** the sensor binary still initializes its active nmap scanner at
> startup and exits if `nmap` is absent, so *running the sensor* today still requires
> nmap on Unix even though this discovery source does not. Making the active scanner
> optional, so ARP-cache discovery can run standalone, is a follow-up.

### Passive read vs. optional sweep

- **Reader (default, passive):** polls the neighbor cache every `--arp-poll-interval`
  (30s default). It reports mapping edges, not periodic liveness. A device that has
  been silent since boot may not appear until something talks to it, and cache presence
  by itself never means the device is currently online.
- **Sweeper (`--arp-sweep`, default OFF, active):** to surface silent hosts, an optional
  warmer briefly touches a few common ports on each address in the local subnet
  (TCP 80/443, UDP 9/33434) so the kernel resolves their MACs into the cache. It opens
  **no raw sockets** — just ordinary `net.Dial` connects/writes, so it stays
  unprivileged. It is bounded for the Pi 4 (concurrency-capped, short per-dial timeout)
  and refuses subnets larger than ~1024 hosts (a `/22`) rather than scanning a huge range.
  Every probe requests the IPv4 source address resolved on the selected link. This
  strongly guides ordinary routing but is not an OS-level interface bind; unusual
  policy routing can still choose another path. Only neighbor rows revalidated on the
  selected interface are accepted as identity evidence.

Because the sweep is active network behavior, it is off unless you opt in.

> **Self-noise caveat:** when the sweeper is enabled, the sensor's own TCP-80/443 and
> UDP-9/33434 touches are real packets on the wire. If this host's own DNS/traffic is
> also being observed, those probes can appear in the sensor's own event stream — the
> sensor watching itself warm the cache. This is expected; it is why the sweep is opt-in.

### Flags

| Flag                   | Default | Meaning                                                        |
|------------------------|---------|----------------------------------------------------------------|
| `--arp-discovery`      | `true`  | Read the OS neighbor cache (passive, unprivileged)             |
| `--arp-sweep`          | `false` | Warm the cache with an unprivileged TCP/UDP sweep (active)     |
| `--arp-poll-interval`  | `30s`   | How often to read the neighbor cache                           |
| `--arp-sweep-interval` | `5m`    | Re-warm cadence when `--arp-sweep` is set (`<=0` = warm once)  |

`--once` validates the persisted sensor credential with Core, uses a finite delivery
budget, responds to Ctrl+C/SIGTERM, drains its sources on every return path, and exits
non-zero when Core is blackholed, rejects the credential, or never fully accepts a batch.
The long-running service retains context-cancellable unlimited retries for transient Core
outages. A terminal 401/403 is different: it pauses scanning, stops DNS and passive-host
HTTP retries, safely drains capture input, and directs the operator to re-enroll with a
fresh reset code bound to that sensor identity.
