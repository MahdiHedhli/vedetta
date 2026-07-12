-- unifi_transform.lua
-- Vedetta collector transform for UniFi firewall syslog (spec 001).
--
-- Entry point (Fluent Bit `lua` filter): unifi_to_event(tag, timestamp, record)
--   Input record comes from the rfc3164 syslog parser and carries at least a
--   "message" (the syslog MSG body) plus "host"/"pri" context.
--
-- Return contract (Fluent Bit filter_lua):
--   -1, ts, record  -> drop the record (non-firewall UniFi noise, malformed)
--    1, ts, record  -> replace with a single normalized firewall_log Event
--    2, ts, {a, b}   -> replace with MULTIPLE records (used when a WAN-inbound
--                       drop both flushes a due rollup AND ... ; here we use 2
--                       only to flush a matured rollup event standalone)
--
-- Normalized Event shape (contracts/unifi-syslog-cef.md section 4):
--   { event_id, event_type="firewall_log", timestamp, source_ip, source_hash="",
--     blocked, anomaly_score=0.0, network_segment, threat_desc,
--     tags = {...}, metadata = <json string> }
--
-- ---------------------------------------------------------------------------
-- ROLLUP / THROTTLE DEFAULTS (spec 001 T1.3)
-- ---------------------------------------------------------------------------
--   WAN-inbound drops are internet background radiation (scanners hitting the
--   WAN IP). They are NOT stored individually. Instead they are accumulated per
--   window and flushed as ONE rollup event (tag "wan_scan_noise", counts in
--   metadata). Defaults, mirrored in corpus/README.md and plan.md:
--     ROLLUP_WINDOW_SECONDS = 900   (15 minutes)
--   Sustained firewall event throughput is additionally capped by a Fluent Bit
--   `throttle` filter in fluent-bit.conf:
--     THROTTLE = 2000 events / 60s window   (excess is sampled, not queued)
--   These are conservative Pi-4-first defaults; Phase 5 live validation may
--   retune the rollup window against observed volume.
-- ---------------------------------------------------------------------------

local ROLLUP_WINDOW_SECONDS = 900   -- 15 minutes (T1.3 default)
local RAW_LOG_MAX = 1024            -- truncate metadata.raw_log to 1 KB
local MALFORMED_LOG_EVERY = 100     -- sample 1 malformed line per N drops

-- Well-known multicast / broadcast destinations (tagged fw:multicast, then
-- matched by the seeded whitelist rule wl-fw-multicast-broadcast, migration 018).
local MULTICAST_DST = {
    ["224.0.0.251"]     = true,  -- mDNS
    ["239.255.255.250"] = true,  -- SSDP
    ["255.255.255.255"] = true,  -- limited broadcast
    ["224.0.0.1"]       = true,  -- all-hosts multicast
    ["224.0.0.22"]      = true,  -- IGMP
}

-- ===========================================================================
-- Rollup + malformed counters (module state; persists across calls within one
-- Fluent Bit process, exactly what we want for windowed aggregation).
-- ===========================================================================
local rollup = {
    window_start = nil,   -- epoch seconds of current window start
    count        = 0,
    unique_src   = {},    -- set of source IPs
    port_counts  = {},    -- dst_port -> count
    interface    = nil,
    dialect      = nil,
    gateway      = nil,
}
local malformed_seen = 0

-- ===========================================================================
-- Small helpers
-- ===========================================================================

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Every emitted record needs an occurrence boundary that survives Fluent Bit's
-- output retries.  Generate it here, in the filter, before the transformed
-- record enters Fluent Bit's buffering layer.  Linux (the supported collector
-- runtime) supplies a kernel UUID; the fallback is only for standalone Lua
-- tests and non-Linux development hosts.
local function collector_boot_nonce()
    local f = io.open("/proc/sys/kernel/random/uuid", "r")
    if f then
        local value = trim(f:read("*l") or "")
        f:close()
        if value ~= "" then return value end
    end
    local address = tostring({}):gsub("[^%w]", "")
    return string.format("%x-%s", os.time(), address)
end

local observation_boot_id = collector_boot_nonce()
local observation_sequence = 0

local function assign_observation_id(event)
    if event and (event.event_id == nil or event.event_id == "") then
        observation_sequence = observation_sequence + 1
        event.event_id = "unifi-" .. observation_boot_id .. "-" .. tostring(observation_sequence)
    end
    return event
end

local function is_multicast(dst)
    if not dst or dst == "" then return false end
    if MULTICAST_DST[dst] then return true end
    -- 224.0.0.0/4 multicast range, 255.x broadcast-ish
    local a = dst:match("^(%d+)%.")
    if a then
        a = tonumber(a)
        if a >= 224 and a <= 239 then return true end
        if a == 255 then return true end
    end
    return false
end

-- RFC 1918 / link-local / CGNAT + RFC 5737 documentation nets treated as
-- "private / LAN-side" for source_ip selection and direction inference.
-- RFC 5737 blocks (192.0.2/198.51.100/203.0.113) are documentation ranges; we
-- classify 192.0.2.x and 198.51.100.x as LAN-side and 203.0.113.x as WAN-side
-- so the synthetic corpus exercises both directions deterministically.
local function is_private(ip)
    if not ip or ip == "" then return false end
    if ip:match("^10%.") then return true end
    if ip:match("^192%.168%.") then return true end
    if ip:match("^169%.254%.") then return true end
    local o1, o2 = ip:match("^(%d+)%.(%d+)%.")
    if o1 then
        o1, o2 = tonumber(o1), tonumber(o2)
        if o1 == 172 and o2 >= 16 and o2 <= 31 then return true end
        if o1 == 100 and o2 >= 64 and o2 <= 127 then return true end  -- CGNAT
    end
    -- RFC 5737 documentation ranges used as synthetic LAN in the corpus:
    if ip:match("^192%.0%.2%.") then return true end
    if ip:match("^198%.51%.100%.") then return true end
    return false
end

-- Minimal JSON string encoder (only what our metadata needs). No external deps
-- so the transform runs under bare Lua and Fluent Bit's embedded Lua alike.
local function json_escape(s)
    s = tostring(s)
    s = s:gsub("\\", "\\\\")
    s = s:gsub('"', '\\"')
    s = s:gsub("\n", "\\n")
    s = s:gsub("\r", "\\r")
    s = s:gsub("\t", "\\t")
    -- strip other control chars
    s = s:gsub("[%z\1-\8\11\12\14-\31]", "")
    return s
end

-- Encode an ordered list of {key, value, kind} into a JSON object string.
-- kind: "s" string, "n" number, "b" bool, "raw" already-encoded fragment.
local function encode_metadata(pairs_list)
    local parts = {}
    for _, kv in ipairs(pairs_list) do
        local k, v, kind = kv[1], kv[2], kv[3]
        if v ~= nil then
            local frag
            if kind == "n" then
                frag = tostring(v)
            elseif kind == "b" then
                frag = v and "true" or "false"
            elseif kind == "raw" then
                frag = v
            else
                frag = '"' .. json_escape(v) .. '"'
            end
            parts[#parts + 1] = '"' .. json_escape(k) .. '":' .. frag
        end
    end
    return "{" .. table.concat(parts, ",") .. "}"
end

-- Map raw UniFi action tokens to canonical actions.
local function normalize_action(raw)
    if not raw then return nil end
    local a = raw:lower()
    if a == "accept" or a == "allow" or a == "pass" or a == "a" then
        return "allow"
    elseif a == "drop" or a == "deny" or a == "d" then
        return "drop"
    elseif a == "reject" or a == "r" then
        return "reject"
    elseif a == "block" then
        return "block"
    end
    return nil
end

local function normalize_proto(raw)
    if not raw then return nil end
    return raw:lower()
end

-- ===========================================================================
-- Timestamp handling. The rfc3164 parser hands Fluent Bit an epoch timestamp,
-- so we normally trust the `timestamp` arg. For standalone testing we also
-- accept a numeric epoch and format ISO 8601 UTC.
-- ===========================================================================
local function iso8601(epoch)
    if type(epoch) ~= "number" then return nil end
    return os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(epoch))
end

-- ===========================================================================
-- Rollup: accumulate a WAN-inbound drop; return a flushed rollup Event (as a
-- normalized record) if the window matured, else nil.
-- ===========================================================================
local function rollup_add(epoch, src, dst_port, iface, dialect, gateway)
    local flushed = nil
    if rollup.window_start == nil then
        rollup.window_start = epoch
    elseif epoch - rollup.window_start >= ROLLUP_WINDOW_SECONDS then
        flushed = rollup_flush()
        rollup.window_start = epoch
    end
    rollup.count = rollup.count + 1
    if src and src ~= "" then rollup.unique_src[src] = true end
    if dst_port then
        rollup.port_counts[dst_port] = (rollup.port_counts[dst_port] or 0) + 1
    end
    rollup.interface = iface or rollup.interface
    rollup.dialect = dialect or rollup.dialect
    rollup.gateway = gateway or rollup.gateway
    return flushed
end

-- Flush the open rollup if its window has fully elapsed relative to `now`
-- (wall clock), independent of whether a new WAN-inbound drop has arrived.
-- Returns a flushed rollup Event or nil. This is what prevents an accumulated
-- window from sitting in module state indefinitely after a scan burst stops:
-- rollup_add only flushes when the NEXT WAN drop crosses the boundary, so a
-- burst followed by silence would otherwise never emit until scanning resumes.
-- Called on EVERY unifi_to_event invocation (any line, not only WAN drops).
function rollup_flush_if_due(now)
    if rollup.count == 0 or rollup.window_start == nil then return nil end
    if type(now) ~= "number" then return nil end
    if now - rollup.window_start >= ROLLUP_WINDOW_SECONDS then
        return rollup_flush()
    end
    return nil
end

-- Build the rollup Event from accumulated state and reset the accumulator.
function rollup_flush()
    if rollup.count == 0 then return nil end

    local unique = 0
    for _ in pairs(rollup.unique_src) do unique = unique + 1 end

    -- top dst ports (sorted desc by count, take up to 5)
    local ports = {}
    for p, c in pairs(rollup.port_counts) do
        ports[#ports + 1] = { port = p, count = c }
    end
    table.sort(ports, function(a, b)
        if a.count == b.count then return a.port < b.port end
        return a.count > b.count
    end)
    local top = {}
    for i = 1, math.min(5, #ports) do
        top[#top + 1] = '{"port":' .. ports[i].port ..
                        ',"count":' .. ports[i].count .. '}'
    end
    local top_json = "[" .. table.concat(top, ",") .. "]"

    local count = rollup.count
    local win_ts = rollup.window_start

    local meta = encode_metadata({
        { "rollup", "true", "raw" },
        { "window_seconds", ROLLUP_WINDOW_SECONDS, "n" },
        { "count", count, "n" },
        { "unique_src", unique, "n" },
        { "top_dst_ports", top_json, "raw" },
        { "interface", rollup.interface, "s" },
        { "gateway", rollup.gateway, "s" },
        { "dialect", rollup.dialect, "s" },
    })

    local ev = {
        event_type      = "firewall_log",
        source_hash     = "",
        source_ip       = "",
        blocked         = true,
        anomaly_score   = 0.0,
        network_segment = "default",
        tags            = { "source:unifi", "fw:drop", "dir:in", "wan_scan_noise" },
        threat_desc     = "WAN inbound scan noise: " .. count ..
                          " drops in " .. math.floor(ROLLUP_WINDOW_SECONDS / 60) .. "m",
        metadata        = meta,
    }
    local ts = iso8601(win_ts)
    if ts then ev.timestamp = ts end

    -- reset
    rollup.count = 0
    rollup.unique_src = {}
    rollup.port_counts = {}
    rollup.interface = nil
    rollup.dialect = nil
    rollup.gateway = nil
    rollup.window_start = nil

    return ev
end

-- ===========================================================================
-- CEF parsing (Dialect A)
-- ===========================================================================
-- Returns a fields table {src, spt, dst, dpt, proto, act, in, out, smac, rule,
-- name, severity} or nil if not a CEF firewall line.
local function parse_cef(msg)
    -- Locate the CEF: header anywhere in the message.
    local cef = msg:match("(CEF:0|.+)$")
    if not cef then return nil end

    -- Split header (first 7 pipe fields) from extension.
    -- CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|extension
    local h = {}
    local rest = cef
    for i = 1, 7 do
        local field, tail = rest:match("^([^|]*)|(.*)$")
        if not field then return nil end
        h[i] = field
        rest = tail
    end
    local vendor    = h[2]
    local sig_id    = h[5]
    local name      = h[6]
    local severity  = h[7]
    local extension = rest

    if vendor and vendor:lower():find("ubiquiti") == nil then
        -- Not a UniFi CEF line; only UniFi dialect is claimed.
        return nil
    end

    -- Only firewall/security classes are ingested. UniFi uses fwrule / ips /
    -- threat class ids; drop client/admin/system CEF categories.
    local sid = (sig_id or ""):lower()
    local FIREWALL_CLASSES = {
        fwrule = true, firewall = true, fw = true,
    }
    if not FIREWALL_CLASSES[sid] then
        -- Non-firewall CEF category -> caller drops it.
        return { _drop = true }
    end

    -- Parse extension key=value pairs. CEF values may contain spaces; a value
    -- runs until the next " key=" boundary. Collect the byte offset of every
    -- key token first, then slice each value up to the following key.
    local ext = {}
    local keys = {}   -- { {name=, key_start=, val_start=}, ... }
    -- A key is a run of [A-Za-z0-9._] immediately followed by '=' and preceded
    -- by start-of-string or whitespace.
    local i = 1
    while true do
        local ks, ke, name = extension:find("([%w%._]+)=", i)
        if not ks then break end
        -- must be at start or preceded by whitespace to count as a key boundary
        if ks == 1 or extension:sub(ks - 1, ks - 1):match("%s") then
            keys[#keys + 1] = { name = name, key_start = ks, val_start = ke + 1 }
        end
        i = ke + 1
    end
    for idx, kdef in ipairs(keys) do
        local val_end
        if keys[idx + 1] then
            -- value ends just before the whitespace preceding the next key
            val_end = keys[idx + 1].key_start - 1
            -- trim the single boundary space
        else
            val_end = #extension
        end
        local v = trim(extension:sub(kdef.val_start, val_end))
        ext[kdef.name] = v
    end

    local iface_in = ext["deviceInboundInterface"] or ext["in"]
    local iface_out = ext["deviceOutboundInterface"] or ext["out"]
    local rule = ext["cs1"] or ext["msg"]

    return {
        dialect  = "cef",
        src      = ext["src"],
        spt      = ext["spt"],
        dst      = ext["dst"],
        dpt      = ext["dpt"],
        proto    = ext["proto"],
        act      = ext["act"],
        iface    = iface_in,
        iface_out= iface_out,
        smac     = ext["smac"],
        rule     = rule,
        name     = name,
        severity = severity,
    }
end

-- ===========================================================================
-- iptables-style parsing (Dialect B)
-- ===========================================================================
-- Line: kernel: [RULESET-RULENUM-A]IN=<if> OUT=<if> MAC=.. SRC=.. DST=.. ...
local function parse_iptables(msg)
    -- bracket prefix [NAME-NUM-LETTER]  (LETTER in A/D/R)
    local ruleset, rulenum, letter, tail =
        msg:match("%[([%w_]+)%-([%w_]+)%-([ADRadr])%](.*)$")
    if not ruleset then
        -- Some firmwares omit the rule number: [NAME-LETTER]
        local rs, lt, tl = msg:match("%[([%w_]+)%-([ADRadr])%](.*)$")
        if not rs then return nil end
        ruleset, rulenum, letter, tail = rs, nil, lt, tl
    end

    local kv = {}
    for k, v in tail:gmatch("([%w_]+)=([^%s]*)") do
        kv[k] = v
    end

    local action
    local L = letter:upper()
    if L == "A" then action = "allow"
    elseif L == "D" then action = "drop"
    elseif L == "R" then action = "reject"
    end

    local rule = ruleset
    if rulenum then rule = ruleset .. "-" .. rulenum end

    return {
        dialect   = "iptables",
        src       = kv["SRC"],
        spt       = kv["SPT"],
        dst       = kv["DST"],
        dpt       = kv["DPT"],
        proto     = kv["PROTO"],
        act       = action,
        iface     = kv["IN"],
        iface_out = (kv["OUT"] ~= "" and kv["OUT"]) or nil,
        smac      = kv["MAC"],
        rule      = rule,
    }
end

-- ===========================================================================
-- Direction inference from interfaces + IP privateness.
--   IN set, OUT empty          -> inbound to gateway  (dir:in)
--   IN LAN bridge, OUT WAN      -> outbound            (dir:out)
--   IN and OUT both LAN         -> inter-VLAN / local  (dir:local)
-- We also use src/dst privateness as a tie-breaker for CEF (where OUT may be
-- absent): private src + public dst -> out; public src + private dst -> in.
-- ===========================================================================
local function infer_direction(f)
    local has_in = f.iface and f.iface ~= ""
    local has_out = f.iface_out and f.iface_out ~= ""
    local src_priv = is_private(f.src)
    local dst_priv = is_private(f.dst)

    if has_in and not has_out then
        -- inbound to the gateway unless clearly a LAN->WAN with OUT omitted
        if src_priv and not dst_priv then return "out" end
        return "in"
    end
    if has_in and has_out then
        if src_priv and dst_priv then return "local" end
        if src_priv and not dst_priv then return "out" end
        if dst_priv and not src_priv then return "in" end
        return "local"
    end
    -- interface data unavailable: fall back to IP privateness
    if src_priv and not dst_priv then return "out" end
    if dst_priv and not src_priv then return "in" end
    return "local"
end

-- WAN-inbound drop = inbound direction + drop/reject action + public source.
local function is_wan_inbound_drop(f, direction, action)
    if direction ~= "in" then return false end
    if action ~= "drop" and action ~= "reject" and action ~= "block" then
        return false
    end
    if is_private(f.src) then return false end  -- must originate off-LAN
    return true
end

-- ===========================================================================
-- Build the normalized firewall_log Event from parsed fields.
-- ===========================================================================
local function build_event(f, epoch, gateway)
    local action = normalize_action(f.act)
    if not action then return nil end   -- unknown action -> caller drops
    local proto = normalize_proto(f.proto)
    local direction = infer_direction(f)

    local spt = tonumber(f.spt)
    local dpt = tonumber(f.dpt)

    local blocked = (action == "block" or action == "drop" or action == "reject")

    -- source_ip: LAN-side/private IP when determinable (enables device x-ref).
    local source_ip = ""
    if is_private(f.src) then
        source_ip = f.src
    elseif is_private(f.dst) and direction == "in" then
        source_ip = ""   -- pure WAN inbound: leave empty per contract
    end

    -- tags
    local tags = { "source:unifi", "fw:" .. action, "dir:" .. direction }
    local multicast = is_multicast(f.dst)
    if multicast then tags[#tags + 1] = "fw:multicast" end

    -- threat_desc: "<action> <proto> :<dpt> (rule: <rule>)"
    local desc = action
    if proto then desc = desc .. " " .. proto end
    if dpt then desc = desc .. " :" .. dpt end
    if f.rule and f.rule ~= "" then desc = desc .. " (rule: " .. f.rule .. ")" end

    -- raw_log (truncated)
    local raw = f._raw or ""
    if #raw > RAW_LOG_MAX then raw = raw:sub(1, RAW_LOG_MAX) end

    local meta = encode_metadata({
        { "action", action, "s" },
        { "protocol", proto, "s" },
        { "src_ip", f.src, "s" },
        { "src_port", spt, spt and "n" or nil },
        { "src_mac", f.smac, "s" },
        { "dst_ip", f.dst, "s" },
        { "dst_port", dpt, dpt and "n" or nil },
        { "interface", f.iface, "s" },
        { "interface_out", f.iface_out, "s" },
        { "direction", direction, "s" },
        { "rule", f.rule, "s" },
        { "gateway", gateway, "s" },
        { "dialect", f.dialect, "s" },
        { "raw_log", raw, "s" },
    })

    local ev = {
        event_type      = "firewall_log",
        source_hash     = "",
        source_ip       = source_ip,
        blocked         = blocked,
        anomaly_score   = 0.0,
        network_segment = "default",
        tags            = tags,
        threat_desc     = desc,
        metadata        = meta,
    }
    local ts = iso8601(epoch)
    if ts then ev.timestamp = ts end
    return ev, direction, action
end

-- ===========================================================================
-- Core normalization: raw syslog MSG -> (result_kind, event[, event2])
--   kind "event"   : single normalized event, e[1]
--   kind "rollup"  : WAN drop absorbed; e[1] is a flushed rollup or nil
--   kind "drop"    : non-firewall / malformed -> drop
-- Exposed for the standalone test harness.
-- ===========================================================================
local function normalize(msg, epoch, gateway)
    if not msg or msg == "" then
        return "drop"
    end

    -- Dialect commitment (security): a line carrying a CEF:0| header is a CEF
    -- line and MUST be parsed as CEF only. If parse_cef rejects it (non-Ubiquiti
    -- vendor, non-firewall class, or malformed), DROP it — never fall through to
    -- parse_iptables. Otherwise a forged CEF line from a non-Ubiquiti vendor whose
    -- extension happens to contain an iptables-style [NAME-N-D] bracket would be
    -- laundered into a firewall_log event with dialect=iptables, letting any host
    -- on the LAN inject fabricated firewall events (contract section 2.1: only
    -- Ubiquiti CEF is claimed; foreign/non-firewall categories drop at collector).
    local has_cef_header = msg:match("CEF:0|") ~= nil

    local f = parse_cef(msg)
    if has_cef_header then
        if not f or f._drop then
            return "drop"   -- non-Ubiquiti, non-firewall CEF class, or malformed
        end
    else
        -- No CEF header: iptables dialect is the only remaining possibility.
        if not f then
            f = parse_iptables(msg)
        end
    end
    if not f then
        return "drop"   -- not a recognized firewall dialect
    end
    f._raw = msg

    -- Determine direction/action to route WAN-inbound drops into the rollup.
    local action = normalize_action(f.act)
    if not action then
        return "drop"   -- unparseable action
    end
    local direction = infer_direction(f)

    if is_wan_inbound_drop(f, direction, action) then
        local dpt = tonumber(f.dpt)
        local flushed = rollup_add(epoch, f.src, dpt, f.iface, f.dialect, gateway)
        return "rollup", flushed
    end

    local ev = build_event(f, epoch, gateway)
    if not ev then return "drop" end
    return "event", ev
end

-- Reconstruct the syslog MSG from a parsed record, undoing the rfc3164 parser's
-- "HOST IDENT: MSG" colon split for CEF lines (ident="CEF", msg="0|...").
local function reconstruct_msg(record)
    local msg = record["message"] or record["raw_log"] or ""
    local ident = record["ident"]
    if ident == "CEF" and msg:match("^%d+|") then
        return "CEF:" .. msg
    elseif ident and ident ~= "kernel" and not msg:match("CEF:0|")
           and msg:match("^%d+|Ubiquiti") then
        return "CEF:" .. msg
    end
    return msg
end

-- ===========================================================================
-- Fluent Bit entry point.
--
-- Timestamp note: the returned record carries an ISO `timestamp` field (from
-- the parsed syslog time). The HTTP output is configured with
-- `Json_date_key timestamp`, so Fluent Bit serializes the record time under the
-- same key; for individual events the two agree. For a flushed rollup we return
-- the triggering line's FB timestamp (start of the *next* window ≈ end of the
-- flushed window), which is the intended "emitted at window boundary" time.
-- `handleIngest` also accepts the [timestamp, record] pair form either way.
-- ===========================================================================
function unifi_to_event(tag, timestamp, record)
    -- Fluent Bit passes timestamp as a number (epoch) or a table in some
    -- builds; coerce to a number.
    local epoch
    if type(timestamp) == "number" then
        epoch = timestamp
    elseif type(timestamp) == "table" then
        epoch = timestamp["sec"] or timestamp[1] or os.time()
    else
        epoch = os.time()
    end

    local msg = reconstruct_msg(record)
    local gateway = record["host"]

    -- Wall-clock rollup flush (Finding 2): emit an open, matured rollup on ANY
    -- incoming line once its window has elapsed, measured against os.time() (not
    -- the parsed syslog epoch, so gateway clock skew / RFC-3164 year misinference
    -- cannot shift or stall the boundary). Without this, a scan burst followed by
    -- silence would keep the accumulated window in module state until the next
    -- burst — defeating the "is my WAN being probed" view and losing the window
    -- on process restart. Fluent Bit runs this filter on every firewall.syslog
    -- record, so any traffic (firewall or otherwise) ticks the check.
    local due = rollup_flush_if_due(os.time())

    local kind, a, b = normalize(msg, epoch, gateway)

    if kind == "event" then
        if due then
            -- Emit the matured rollup AND this individual event (multi-record).
            return 2, timestamp, { assign_observation_id(due), assign_observation_id(a) }
        end
        return 1, timestamp, assign_observation_id(a)
    elseif kind == "rollup" then
        -- `a` here is a rollup flushed by rollup_add crossing the boundary on
        -- this WAN drop. `due` is a rollup the wall-clock check already flushed.
        -- At most one can be non-nil (rollup_flush_if_due drains the window
        -- before normalize re-opens it), but coalesce defensively.
        local flushed = due or a
        if flushed then
            return 1, timestamp, assign_observation_id(flushed)
        end
        -- Drop absorbed into the current window; no row emitted.
        return -1, timestamp, record
    else -- "drop"
        if due then
            -- This line drops, but a matured rollup is due — emit the rollup.
            return 1, timestamp, assign_observation_id(due)
        end
        malformed_seen = malformed_seen + 1
        if (malformed_seen % MALFORMED_LOG_EVERY) == 1 then
            -- Sampled logging for parser improvement (FR-9). Fluent Bit
            -- surfaces stdout in collector logs.
            print("[unifi_transform] dropped non-firewall/malformed line (sample #"
                  .. malformed_seen .. "): " .. tostring(msg):sub(1, 200))
        end
        return -1, timestamp, record
    end
end

-- Export internals for the standalone test harness (harmless under Fluent Bit).
return {
    normalize        = normalize,
    reconstruct_msg  = reconstruct_msg,
    rollup_flush     = rollup_flush,
    rollup_flush_if_due = rollup_flush_if_due,
    parse_cef      = parse_cef,
    parse_iptables = parse_iptables,
    normalize_action = normalize_action,
    infer_direction  = infer_direction,
    _rollup_state    = function() return rollup end,
}
