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
--   source_hash   = client IP (hashed by Core in future; raw for now)
--   domain        = domain
--   query_type    = query_type
--   blocked       = true if action contains "blocked" (Pi-hole gravity)

function pihole_to_event(tag, timestamp, record)
    local new = {}

    new["event_type"]   = "dns_query"
    new["domain"]       = record["domain"] or ""
    new["query_type"]   = record["query_type"] or ""
    new["source_hash"]  = record["client"] or "unknown"

    -- Pi-hole logs "gravity blocked" or "/etc/pihole/gravity" for blocked queries
    local action = record["action"] or ""
    if string.find(action, "block") or string.find(action, "gravity") then
        new["blocked"] = true
    else
        new["blocked"] = false
    end

    return 1, timestamp, new
end
