-- run_tests.lua — golden-file test runner for unifi_transform.lua (spec 001 T2.1/T2.2).
--
-- For each corpus input under specs/001-unifi-log-ingestion/corpus/inputs/,
-- runs the transform and compares the normalized event stream against the
-- committed expected fixture under .../corpus/expected/<name>.expected.json
-- (one compact-JSON event per line, in emission order).
--
-- Also runs explicit rollup + dialect-detection assertions (T2.2).
--
-- Pure Lua. Exit 0 on all-pass, 1 on any failure.
--
-- Usage:
--   lua collector/test/run_tests.lua                # uses default corpus dir
--   CORPUS=/path lua collector/test/run_tests.lua   # override corpus root

local function script_dir()
    local src = debug.getinfo(1, "S").source
    local path = src:match("^@(.*)$") or src
    return path:match("^(.*/)") or "./"
end
local HERE = script_dir()
local H = dofile(HERE .. "harness.lua")

local CORPUS = os.getenv("CORPUS")
    or (HERE .. "../../specs/001-unifi-log-ingestion/corpus")
local INPUTS = CORPUS .. "/inputs"
local EXPECTED = CORPUS .. "/expected"

-- ---- compact deterministic JSON encoder (keys sorted) ----
local function enc(v)
    local t = type(v)
    if t == "string" then
        return '"' .. v:gsub("\\", "\\\\"):gsub('"', '\\"') .. '"'
    elseif t == "number" then
        -- keep 0.0 as 0.0 for anomaly_score readability
        if v == math.floor(v) and tostring(v):find("%.") == nil then
            return tostring(v)
        end
        return tostring(v)
    elseif t == "boolean" then
        return v and "true" or "false"
    elseif t == "table" then
        if #v > 0 then
            local p = {}
            for _, x in ipairs(v) do p[#p + 1] = enc(x) end
            return "[" .. table.concat(p, ",") .. "]"
        else
            local keys = {}
            for k in pairs(v) do keys[#keys + 1] = k end
            table.sort(keys)
            local p = {}
            for _, k in ipairs(keys) do p[#p + 1] = '"' .. k .. '":' .. enc(v[k]) end
            return "{" .. table.concat(p, ",") .. "}"
        end
    else
        return "null"
    end
end

local pass, fail = 0, 0
local function ok(name) pass = pass + 1; print("  PASS " .. name) end
local function bad(name, detail)
    fail = fail + 1
    print("  FAIL " .. name)
    if detail then print("       " .. detail) end
end

local function file_exists(p)
    local f = io.open(p, "r"); if f then f:close(); return true end; return false
end

local function write_lines(path, lines)
    local f = assert(io.open(path, "w"))
    for _, l in ipairs(lines) do f:write(l, "\n") end
    f:close()
end

local function read_expected(path)
    local f = io.open(path, "r"); if not f then return nil end
    local lines = {}
    for l in f:lines() do if l:match("%S") then lines[#lines + 1] = l end end
    f:close()
    return lines
end

-- ---- golden comparison per corpus file ----
local UPDATE = os.getenv("UPDATE") == "1"
local cases = { "cef", "iptables", "noise" }

print("== golden-file cases ==")
for _, name in ipairs(cases) do
    -- fresh transform state per file: reload the module by clearing rollup.
    H.T.rollup_flush()  -- drain any residue
    local input = INPUTS .. "/" .. name .. ".log"
    if not file_exists(input) then
        bad(name, "missing input " .. input)
    else
        local events = H.run(H.read_lines(input))
        local got = {}
        for _, e in ipairs(events) do got[#got + 1] = enc(e) end

        local exp_path = EXPECTED .. "/" .. name .. ".expected.json"
        if UPDATE then
            write_lines(exp_path, got)
            ok(name .. " (updated fixture)")
        else
            local exp = read_expected(exp_path)
            if not exp then
                bad(name, "missing expected fixture " .. exp_path ..
                    " (run with UPDATE=1 to create)")
            elseif #exp ~= #got then
                bad(name, "event count: expected " .. #exp .. " got " .. #got)
                for i = 1, math.max(#exp, #got) do
                    if exp[i] ~= got[i] then
                        print("       [" .. i .. "] exp: " .. tostring(exp[i]))
                        print("       [" .. i .. "] got: " .. tostring(got[i]))
                    end
                end
            else
                local mismatch = false
                for i = 1, #exp do
                    if exp[i] ~= got[i] then
                        mismatch = true
                        print("       [" .. i .. "] exp: " .. exp[i])
                        print("       [" .. i .. "] got: " .. got[i])
                    end
                end
                if mismatch then bad(name) else ok(name) end
            end
        end
    end
end

-- ---- durable per-observation identity ----
-- Two legitimate identical firewall observations can share the same parsed
-- second.  The filter must distinguish them, while a retry of an already
-- transformed/buffered record retains the same ID.
print("== observation identity ==")
do
    H.T.rollup_flush()
    local record = {
        host = "gw",
        ident = "kernel",
        message = "[LAN_IN-3001-D]IN=br5 OUT=eth8 SRC=192.0.2.45 DST=203.0.113.10 PROTO=TCP SPT=50000 DPT=443",
    }
    local code1, _, first = unifi_to_event("firewall.syslog", 1751537722, record)
    local code2, _, second = unifi_to_event("firewall.syslog", 1751537722, record)
    if code1 == 1 and code2 == 1 and first.event_id and second.event_id and
       first.event_id ~= second.event_id then
        ok("identical same-second observations receive distinct durable IDs")
    else
        bad("same-second observation IDs",
            "first=" .. tostring(first and first.event_id) ..
            " second=" .. tostring(second and second.event_id))
    end
    local retained_id = first and first.event_id
    local buffered_retry = first
    if retained_id and buffered_retry.event_id == retained_id then
        ok("buffered retry retains the transformed observation ID")
    else
        bad("buffered retry observation ID")
    end
end

-- ---- explicit rollup assertion (T2.2) ----
print("== rollup assertions ==")
do
    H.T.rollup_flush()
    local wanfile = INPUTS .. "/wan_drops.log"
    if not file_exists(wanfile) then
        bad("wan_drops rollup", "missing " .. wanfile)
    else
        local events = H.run(H.read_lines(wanfile))
        if #events ~= 1 then
            bad("wan_drops single rollup", "expected exactly 1 event, got " .. #events)
        else
            local m = events[1].metadata
            local count = tonumber(m:match('"count":(%d+)'))
            local has_tag = false
            for _, t in ipairs(events[1].tags) do
                if t == "wan_scan_noise" then has_tag = true end
            end
            local nlines = #H.read_lines(wanfile)
            if count == nlines and has_tag and events[1].source_ip == "" then
                ok("wan_drops rollup count=" .. count .. " (=" .. nlines .. " lines)")
            else
                bad("wan_drops rollup",
                    "count=" .. tostring(count) .. " lines=" .. nlines ..
                    " tag=" .. tostring(has_tag))
            end
        end
    end
end

-- outbound blocks in the same window still emit individually (mixed input)
do
    H.T.rollup_flush()
    local mixed = {
        -- 3 WAN inbound drops (rollup) + 1 outbound block (individual)
        "<4>Jul  3 10:15:01 gw kernel: [WAN_LOCAL-default-D]IN=eth8 OUT= MAC=00:00:5E:00:53:01 SRC=203.0.113.5 DST=198.51.100.2 PROTO=TCP SPT=1 DPT=22",
        "<4>Jul  3 10:15:02 gw kernel: [WAN_LOCAL-default-D]IN=eth8 OUT= MAC=00:00:5E:00:53:01 SRC=203.0.113.6 DST=198.51.100.2 PROTO=TCP SPT=2 DPT=23",
        "<4>Jul  3 10:15:03 gw kernel: [LAN_IN-3001-D]IN=br5 OUT=eth8 MAC=00:00:5E:00:53:0B SRC=192.0.2.45 DST=203.0.113.10 PROTO=TCP SPT=5 DPT=445",
        "<4>Jul  3 10:15:04 gw kernel: [WAN_LOCAL-default-D]IN=eth8 OUT= MAC=00:00:5E:00:53:01 SRC=203.0.113.7 DST=198.51.100.2 PROTO=TCP SPT=3 DPT=22",
    }
    local events = H.run(mixed)
    -- expect: 1 individual outbound block + 1 rollup(count=3)
    local individ, rollupc = 0, nil
    for _, e in ipairs(events) do
        local isroll = e.metadata:find('"rollup":true') ~= nil
        if isroll then rollupc = tonumber(e.metadata:match('"count":(%d+)'))
        else individ = individ + 1 end
    end
    if individ == 1 and rollupc == 3 then
        ok("mixed window: 1 individual block + rollup(count=3)")
    else
        bad("mixed window", "individual=" .. individ .. " rollup_count=" .. tostring(rollupc))
    end
end

-- ---- wall-clock rollup flush (Finding 2) ----
-- A scan burst followed by silence must still emit its rollup within ~1 window,
-- driven by wall-clock elapse (rollup_flush_if_due) rather than only by the next
-- WAN drop crossing the boundary. Also assert it is measured against the passed
-- `now`, so gateway clock skew in the parsed epoch cannot stall the boundary.
print("== wall-clock rollup flush ==")
do
    local T = H.T
    T.rollup_flush()  -- start clean
    local base = 1751537722
    -- 3 WAN inbound drops open a window at epoch `base` (absorbed, no emit).
    for i = 1, 3 do
        local line = "[WAN_LOCAL-default-D]IN=eth8 OUT= SRC=203.0.113." .. i ..
                     " DST=198.51.100.2 PROTO=TCP SPT=1 DPT=22"
        local kind, a = T.normalize(line, base, "gw")
        if kind ~= "rollup" or a ~= nil then
            bad("wall-clock flush setup", "line " .. i .. " kind=" .. tostring(kind))
        end
    end
    -- Before the window elapses: no flush.
    local early = T.rollup_flush_if_due(base + 10)
    -- After the window fully elapses (wall clock): the open rollup flushes even
    -- though NO further WAN drop ever arrived.
    local late = T.rollup_flush_if_due(base + 900)
    if early == nil and late ~= nil and late.metadata:match('"count":(%d+)') == "3" then
        ok("open rollup flushes on wall-clock elapse (count=3, no trailing drop)")
    else
        bad("wall-clock flush",
            "early=" .. tostring(early) .. " late=" .. tostring(late and late.metadata))
    end
    -- Window is now drained: a subsequent due-check with no open window is a no-op.
    if T.rollup_flush_if_due(base + 5000) == nil then
        ok("wall-clock flush is a no-op with no open window")
    else
        bad("wall-clock flush no-op", "expected nil")
    end
end

-- ---- dialect detection assertions (T2.1) ----
print("== dialect detection ==")
do
    local T = H.T
    local checks = {
        { "CEF firewall", "CEF:0|Ubiquiti|UniFi Network|9|fwrule|Block|3|src=192.0.2.1 dst=203.0.113.1 dpt=80 proto=TCP act=block deviceInboundInterface=br0 deviceOutboundInterface=eth8", "event" },
        { "CEF non-fw dropped", "CEF:0|Ubiquiti|UniFi Network|9|client|Connected|1|src=192.0.2.1 msg=assoc", "drop" },
        { "CEF non-ubiquiti dropped", "CEF:0|Acme|FW|1|fwrule|Block|3|src=203.0.113.1 dst=198.51.100.1 act=block", "drop" },
        -- Finding 1 (dialect commitment / injection): a forged non-Ubiquiti CEF
        -- line whose extension carries an iptables-style [NAME-N-D] bracket must
        -- DROP — it must NOT fall through to parse_iptables and be laundered into
        -- a firewall_log event with dialect=iptables.
        { "CEF-header forged iptables dropped", "CEF:0|Acme|FW|1|fwrule|Block|3|msg=[LAN_IN-3001-D]IN=br5 SRC=192.0.2.1 DST=192.0.2.2 act=block", "drop" },
        { "iptables drop", "[LAN_IN-3001-D]IN=br5 OUT=br0 SRC=192.0.2.45 DST=192.0.2.10 PROTO=TCP SPT=1 DPT=445", "event" },
        { "garbage dropped", "this is not a firewall line", "drop" },
        { "empty dropped", "", "drop" },
    }
    for _, c in ipairs(checks) do
        T.rollup_flush()
        local kind = T.normalize(c[2], 1751537722, "gw")
        if kind == c[3] then ok(c[1] .. " -> " .. kind)
        else bad(c[1], "expected " .. c[3] .. " got " .. tostring(kind)) end
    end
end

-- ---- Pi-hole identity contract ----
-- The collector must pass the raw LAN client address in source_ip so Core can
-- derive the per-install HMAC. Putting it in source_hash would let the caller
-- choose grouping identity and would persist a raw address in a pseudonym field.
print("== Pi-hole transform identity ==")
do
    dofile(HERE .. "../config/pihole_transform.lua")
    local record = {
        domain = "lookup.example",
        query_type = "A",
        client = "192.0.2.55",
        action = "query",
    }
    local _, _, event = pihole_to_event("dns.pihole", 1751537722, record)
    local _, _, same_second = pihole_to_event("dns.pihole", 1751537722, record)
    if event.source_ip == "192.0.2.55" and event.source_hash == "" and
       event.dns_source == "pihole" and event.event_id and same_second.event_id and
       event.event_id ~= same_second.event_id then
        ok("raw client uses source_ip; Core owns source_hash")
        ok("identical same-second Pi-hole observations receive distinct durable IDs")
        local buffered_retry = event
        if buffered_retry.event_id == event.event_id then
            ok("Pi-hole buffered retry retains the transformed observation ID")
        else
            bad("Pi-hole buffered retry observation ID")
        end
    else
        bad("Pi-hole source identity",
            "source_ip=" .. tostring(event.source_ip) ..
            " source_hash=" .. tostring(event.source_hash) ..
            " dns_source=" .. tostring(event.dns_source) ..
            " event_id=" .. tostring(event.event_id) ..
            " second_event_id=" .. tostring(same_second.event_id))
    end
end

print("")
print(string.format("RESULT: %d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
