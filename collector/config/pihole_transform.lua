-- pihole_transform.lua
-- Maps Fluent Bit pihole parser output to Vedetta Event schema.
--
-- Input fields (from pihole parser):
--   action     = query | reply | forwarded | cached
--   query_type = A | AAAA | MX | TXT | CNAME | SRV | PTR
--   domain     = example.com
--   client     = 192.168.1.42
--   pid        = dnsmasq pid (discarded)
--
-- Output fields (Vedetta Event):
--   event_type    = "dns_query"
--   source_ip     = client IP (kept local; Core derives its private HMAC)
--   source_hash   = empty (caller-controlled pseudonyms are not trusted)
--   dns_source    = "pihole"
--   domain        = domain
--   query_type    = query_type
--   blocked       = true if action contains "blocked" (Pi-hole gravity)

-- Assign an occurrence boundary in the filter before Fluent Bit buffers the
-- transformed record. Output retries then retain the same ID, while two
-- legitimate identical log lines in Pi-hole's second-resolution timestamp
-- remain distinct.
local function pihole_boot_nonce()
    local f = io.open("/proc/sys/kernel/random/uuid", "r")
    if f then
        local value = (f:read("*l") or ""):gsub("^%s+", ""):gsub("%s+$", "")
        f:close()
        if value ~= "" then return value end
    end
    local address = tostring({}):gsub("[^%w]", "")
    return string.format("%x-%s", os.time(), address)
end

local pihole_observation_boot_id = pihole_boot_nonce()
local pihole_observation_sequence = 0

function pihole_to_event(tag, timestamp, record)
    local new = {}

    pihole_observation_sequence = pihole_observation_sequence + 1
    new["event_id"]     = "pihole-" .. pihole_observation_boot_id .. "-" .. tostring(pihole_observation_sequence)
    new["event_type"]   = "dns_query"
    new["domain"]       = record["domain"] or ""
    new["query_type"]   = record["query_type"] or ""
    new["source_ip"]    = record["client"] or ""
    new["source_hash"]  = ""
    new["dns_source"]   = "pihole"
    new["network_segment"] = "default"

    -- Pi-hole logs "gravity blocked" or "/etc/pihole/gravity" for blocked queries
    local action = record["action"] or ""
    if string.find(action, "block") or string.find(action, "gravity") then
        new["blocked"] = true
    else
        new["blocked"] = false
    end

    return 1, timestamp, new
end
