-- Sensor actionability columns.
-- events.server_ip: DNS server / destination side of the query, reported by sensors
--                   (complements source_ip from 011 for source/dest visibility).
-- devices.services: services advertised by the host via passive discovery
--                   (mDNS/SSDP TXT/PTR records), stored as a JSON array of strings.
--
-- Columns already added by earlier migrations and therefore NOT repeated here:
--   events.source_ip, events.threat_desc, events.metadata  (011)
--   events.dns_source                                      (008)
--   events.acknowledged, events.ack_reason                 (012)

ALTER TABLE events ADD COLUMN server_ip TEXT DEFAULT '';

ALTER TABLE devices ADD COLUMN services TEXT DEFAULT '[]';
