# Contract: `POST /api/v1/sensor/devices`

> Spec: `specs/004-passive-discovery-correlation/`
> Boundary: native L2 sensor → Docker Core
> Status: Stable (spec 004 adds one additive field, `friendly_name`)

The sensor pushes a batch of discovered hosts to Core over this authenticated
endpoint. Spec 004 adds a single optional field (`friendly_name`) to each host.
All values in examples are synthetic (RFC 5737 IPs, `00:00:5E:00:53:xx` MACs).

## Auth

- Bearer token with `sensor` scope (from `/api/v1/sensor/register`).
- Sensor identity resolved from the token and/or the `X-Sensor-ID` header and
  the `sensor_id` body field (all must agree with the authenticated sensor).

## Request body

```jsonc
{
  "sensor_id": "sensor-abc",          // string; authenticated sensor id
  "cidr": "192.0.2.0/24",             // string; informational (logging)
  "segment": "lan",                    // string; network segment for this batch
                                        //   (default|iot|guest|<named>); "" -> "default"
  "hosts": [
    {
      "ip_address": "192.0.2.57",      // string
      "mac_address": "00:00:5E:00:53:0A", // string; "" when the source (mDNS/SSDP) has no MAC
      "hostname": "chromecast-hall",   // string; optional
      "vendor": "Google",              // string; optional (OUI / DHCP vendor class)
      "open_ports": [8009],            // []int; optional
      "status": "up",                  // string; optional
      "model": "Chromecast Ultra",     // string; optional (mDNS TXT md=, SSDP SERVER)
      "services": ["_googlecast._tcp"],// []string; optional (mDNS/SSDP service types)
      "friendly_name": "Living Room TV",// string; OPTIONAL, ADDED IN SPEC 004
      "discovery_source": "passive_mdns" // string; see enum below
    }
  ]
}
```

### `discovery_source` enum

`passive_arp` | `passive_dhcp` | `passive_mdns` | `passive_ssdp` | `nmap_active`

Unchanged by spec 004. Core maps each value to a per-field signal confidence
(mDNS/SSDP > DHCP > ARP/OUI > nmap) when recording provenance.

### `friendly_name` (new in spec 004)

- **Optional, additive.** A human-friendly instance name the device advertises:
  mDNS service-instance label (`Living Room TV._googlecast._tcp.local` →
  `Living Room TV`), mDNS TXT `fn=`/`n=`, or an SSDP-derived name.
- Core uses it as the highest-precedence automatic `display_name` source (below
  a user `custom_name`) and as an mDNS-name identity alias for continuity
  matching across DHCP churn.
- When absent/empty, Core derives `display_name` from the remaining signals
  exactly as before — no behavior change for old sensors.

## Response

```jsonc
{ "accepted": 1, "new_devices": 1 }
```

`202`/`200` OK. `new_devices` counts hosts that created a brand-new device record
after identity resolution (a re-linked / merged host is NOT counted as new).

## Compatibility rules (additive-only)

| Scenario | Behavior |
| --- | --- |
| **New sensor → old Core** | Old Core's JSON decoder drops the unknown `friendly_name` field; everything else works. Labels are simply less rich. |
| **Old sensor → new Core** | `friendly_name` is absent; Core treats it as empty and derives `display_name` from model/hostname/vendor/IP. No errors. |
| **Field renames** | None. No alias window required. |
| **Removed fields** | None. All pre-spec-004 fields keep their meaning. |

Because the change is purely additive, sensor and Core upgrade independently in
either order (constitution: "sensors and Core upgrade independently").

## Core-side processing (informative)

Per host, in one transaction:
1. **Identity resolution** (ordered): MAC → mDNS name+segment (7d) → unique
   non-generic hostname+segment (7d) → IP+segment (MAC-conflict veto; MAC-less
   both sides requires 24h recency).
2. **Duplicate merge**: if a MAC match and an alias/IP match resolve to different
   records, the MAC-less record is folded into the MAC-bearing one.
3. **Signal write**: each non-empty field is recorded as a
   `(field, value, source, confidence)` signal; canonical device columns are
   recomputed from the highest-confidence signal per field (`user_corrected`
   locks a field at confidence 1.0).
4. **Attachment**: `device_networks` gets/refreshes a `(device, segment)` row;
   `devices.segment`/`ip_address` track the most-recent attachment.
5. **Label**: `display_name` recomputed (custom_name > friendly_name >
   model(+vendor) > cleaned hostname > vendor+MAC-suffix > IP).
