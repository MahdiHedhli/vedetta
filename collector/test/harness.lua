-- harness.lua — shared test harness for unifi_transform.lua
--
-- Emulates the Fluent Bit rfc3164 syslog parser: strips the <PRI>TIMESTAMP HOST
-- IDENT: prefix and hands the transform the MSG body + host, exactly as the
-- collector pipeline does. Then runs unifi_transform.normalize over each line
-- and returns the stream of normalized events (individual + flushed rollups).
--
-- Pure Lua, no Fluent Bit required.

local M = {}

-- Load the transform module. Resolve the transform path robustly: prefer an
-- explicit override (VEDETTA_UNIFI_LUA), else derive from this file's directory
-- via a debug.getinfo lookup (works regardless of which script `dofile`d us).
local function this_dir()
    local src = debug.getinfo(1, "S").source
    local path = src:match("^@(.*)$") or src
    return path:match("^(.*/)") or "./"
end
local here = this_dir()
local transform_path = os.getenv("VEDETTA_UNIFI_LUA")
    or (here .. "../config/unifi_transform.lua")
package.path = here .. "../config/?.lua;" .. package.path
local T = dofile(transform_path)
M.T = T

-- Parse a raw syslog datagram like the rfc3164 parser:
--   <PRI>MMM DD HH:MM:SS HOST IDENT[pid]: MSG   -> host, epoch, msg
-- Also tolerates lines with no valid syslog framing (returns nil).
local MONTHS = { Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12 }

function M.parse_syslog(line)
    -- <PRI>
    local rest = line:gsub("^<%d+>", "")
    -- MMM DD HH:MM:SS
    local mon, day, hh, mm, ss, tail =
        rest:match("^(%a%a%a)%s+(%d+)%s+(%d+):(%d+):(%d+)%s+(.*)$")
    if not mon then return nil end
    -- HOST IDENT[pid]: MSG   — replicate the rfc3164 parser's field split,
    -- including its colon-boundary quirk (CEF lines split ident="CEF").
    local host, after = tail:match("^(%S+)%s+(.*)$")
    if not host then return nil end
    local ident, msg = after:match("^([^%s:%[]+)%[?%d*%]?:%s*(.*)$")
    if not ident then
        -- No "ident: " boundary (e.g. bare "bridge br0: ..."); pass through.
        ident, msg = nil, after
    end
    -- Build a synthetic epoch (fixed year 2026 UTC) so ISO timestamps are stable.
    local monN = MONTHS[mon] or 1
    local epoch = os.time({ year = 2026, month = monN, day = tonumber(day),
                            hour = tonumber(hh), min = tonumber(mm),
                            sec = tonumber(ss), isdst = false })
    -- os.time uses local tz; normalize to a UTC-stable value by re-deriving.
    -- We just need monotonic + deterministic within-window ordering, and the
    -- transform formats with os.date("!...") (UTC). To keep timestamps stable
    -- regardless of the runner's TZ, compute epoch as if the local time WERE
    -- UTC by subtracting the tz offset.
    local off = os.difftime(os.time(os.date("*t", epoch)),
                            os.time(os.date("!*t", epoch)))
    epoch = epoch + off
    return host, epoch, msg, ident
end

-- Run the transform over an array of raw syslog lines. Returns an array of
-- normalized event tables (rollups included, in flush order). A trailing
-- rollup_flush() is appended so any open window is emitted for assertions.
function M.run(lines)
    local out = {}
    for _, line in ipairs(lines) do
        local host, epoch, msg, ident = M.parse_syslog(line)
        if not host then
            -- unparseable framing: feed the raw line -> transform drops it
            host, epoch, msg, ident = nil, os.time(), line, nil
        end
        -- Reconstruct the CEF header exactly as the Fluent Bit entry point does.
        local rec = { message = msg, host = host, ident = ident }
        msg = T.reconstruct_msg(rec)
        local kind, a = T.normalize(msg, epoch, host)
        if kind == "event" then
            out[#out + 1] = a
        elseif kind == "rollup" and a then
            out[#out + 1] = a
        end
        -- "drop" and absorbed rollups produce nothing
    end
    local final = T.rollup_flush()
    if final then out[#out + 1] = final end
    return out
end

function M.read_lines(path)
    local f = assert(io.open(path, "r"))
    local lines = {}
    for l in f:lines() do
        if l:match("%S") then lines[#lines + 1] = l end
    end
    f:close()
    return lines
end

return M
