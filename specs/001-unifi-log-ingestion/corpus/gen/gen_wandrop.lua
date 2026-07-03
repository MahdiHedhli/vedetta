-- gen_wandrop.lua — generate synthetic WAN-inbound drop lines (iptables dialect).
-- All values synthetic: WAN scanners from 203.0.113.0/24, WAN IP 198.51.100.2.
-- Usage: lua gen_wandrop.lua <count> [dst_ports_csv]  > wan_drops.log
--
-- Every line falls inside a single 15-minute window (fixed 10:15:xx second
-- offsets modulo 60) so the rollup golden test yields exactly one rollup event.

local count = tonumber(arg[1]) or 1482
local ports_csv = arg[2] or "22,23,445,3389,80"
local ports = {}
for p in ports_csv:gmatch("%d+") do ports[#ports + 1] = tonumber(p) end

math.randomseed(42)  -- deterministic

for i = 1, count do
    local last = (i % 254) + 1                     -- 203.0.113.1 .. .254
    local sec = i % 60                             -- keep within one window
    local port = ports[(i % #ports) + 1]
    local spt = 1024 + (i % 60000)
    io.write(string.format(
        "<4>Jul  3 10:15:%02d gateway-placeholder kernel: [WAN_LOCAL-default-D]"
        .. "IN=eth8 OUT= MAC=00:00:5E:00:53:01 SRC=203.0.113.%d DST=198.51.100.2 "
        .. "LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=%d DF PROTO=TCP SPT=%d DPT=%d "
        .. "WINDOW=65535 RES=0x00 SYN URGP=0\n",
        sec, last, i, spt, port))
end
