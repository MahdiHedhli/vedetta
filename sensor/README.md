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
| Windows       | the existing `arp -a` reader             |

Reading the cache is **passive** and is **on by default** (`--arp-discovery`). Each
resolved entry is emitted as a discovered host with `discovery_source: "arp"` and flows
through the same pipeline as passive discovery.

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
  (30s default). It only reports hosts the OS has *already* resolved, so a device that
  has been silent since boot may not appear until something talks to it.
- **Sweeper (`--arp-sweep`, default OFF, active):** to surface silent hosts, an optional
  warmer briefly touches a few common ports on each address in the local subnet
  (TCP 80/443, UDP 9/33434) so the kernel resolves their MACs into the cache. It opens
  **no raw sockets** — just ordinary `net.Dial` connects/writes, so it stays
  unprivileged. It is bounded for the Pi 4 (concurrency-capped, short per-dial timeout)
  and refuses subnets larger than ~1024 hosts (a `/22`) rather than scanning a huge range.

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
