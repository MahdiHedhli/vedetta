-- Quick health and SNR summary for the database
-- Usage: docker compose exec -T backend sqlite3 /data/vedetta.db < scripts/db-health.sql

SELECT '=== Vedetta Capture Status ===' as '';

WITH stats AS (
  SELECT 
    COUNT(*) AS total_events,
    SUM(CASE WHEN dns_source = 'simulation' THEN 1 ELSE 0 END) AS sim_events,
    SUM(CASE WHEN dns_source != 'simulation' THEN 1 ELSE 0 END) AS real_events,
    (SELECT MAX(last_seen) FROM devices) AS last_device_update
  FROM events
)
SELECT 
  'Real passive DNS events: ' || real_events || 
  CASE WHEN real_events = 0 THEN ' (still in validation / test phase)' ELSE '' END as status
FROM stats;

SELECT 
  'Simulation / test events: ' || sim_events as status
FROM stats;

SELECT 
  CASE 
    WHEN (julianday('now') - julianday(last_device_update)) * 24 * 60 < 10 
    THEN 'Device discovery: LIVE - sensor actively updating devices (last update ~' || 
         ROUND((julianday('now') - julianday(last_device_update)) * 24 * 60, 1) || ' min ago)'
    ELSE 'Device discovery: Using historical data (last update ' || 
         ROUND((julianday('now') - julianday(last_device_update)) * 24, 1) || ' hours ago)'
  END as status
FROM stats;

SELECT '' as '';
SELECT '=== Live Device Inventory ===' as '';
SELECT 'Total devices: ' || COUNT(*) FROM devices;
SELECT 'By segment:' as info;
SELECT segment, COUNT(*) as c FROM devices GROUP BY segment ORDER BY c DESC;
SELECT 'New devices (first_seen in last 48h): ' || COUNT(*) FROM devices WHERE first_seen > datetime('now', '-48 hours');
SELECT 'Top 5 vendors:' as info;
SELECT vendor, COUNT(*) as c FROM devices WHERE vendor != '' GROUP BY vendor ORDER BY c DESC LIMIT 5;
SELECT 'Sample recent devices:' as info;
SELECT ip_address, hostname, vendor, segment, last_seen FROM devices ORDER BY last_seen DESC LIMIT 3;

SELECT '' as '';
SELECT '=== Live Real Passive DNS (non-simulation events) ===' as '';

WITH real_dns AS (
  SELECT * FROM events 
  WHERE event_type = 'dns_query' 
    AND (dns_source IS NULL OR dns_source != 'simulation')
)
SELECT 'Real DNS queries seen: ' || COUNT(*) as metric FROM real_dns;

SELECT 
  CASE 
    WHEN COUNT(*) = 0 THEN 'No real passive DNS events captured yet. Generate some network traffic and re-run this report.'
    ELSE 'Real DNS events are flowing from your network.'
  END as status
FROM real_dns;

-- Show recent real activity with current device context (for live threat hunting)
SELECT '' as '';
SELECT 'Most recent real DNS events (with current device context):' as '';
SELECT 
  e.timestamp,
  e.domain,
  e.source_ip,
  COALESCE(e.device_vendor, 'Unknown') as event_vendor,
  COALESCE(e.network_segment, 'unknown') as event_segment,
  COALESCE(d.vendor, 'Unknown') as current_vendor,
  COALESCE(d.hostname, '') as current_hostname,
  COALESCE(ROUND(e.anomaly_score, 2), 0) as score,
  e.tags
FROM real_dns e
LEFT JOIN devices d ON d.ip_address = e.source_ip
ORDER BY e.timestamp DESC 
LIMIT 8;

SELECT '' as '';
SELECT 'Real events by network segment (live devices):' as info;
SELECT 
  COALESCE(network_segment, 'unknown') as segment, 
  COUNT(*) as events 
FROM real_dns 
GROUP BY network_segment 
ORDER BY events DESC;

SELECT '' as '';
SELECT 'Top real high-scoring DNS events from live traffic:' as '';
SELECT domain, COALESCE(ROUND(anomaly_score,2),0) as score, tags, network_segment, COALESCE(device_vendor,'Unknown') as vendor, timestamp 
FROM real_dns 
ORDER BY COALESCE(anomaly_score,0) DESC, timestamp DESC 
LIMIT 5;

-- Transition note
SELECT 
  CASE WHEN (SELECT COUNT(*) FROM real_dns) = 0 
  THEN '--- Real passive DNS capture has started. Waiting for first real events to appear in the DB. ---'
  ELSE ''
  END as '';

SELECT '' as '';
SELECT 
  CASE WHEN (SELECT COUNT(*) FROM events WHERE dns_source = 'simulation') > 0 
  THEN '=== Historical Validation / Test Data (from previous simulate-real-enrich runs) ==='
  ELSE '=== Clean Live Capture Mode (no simulation data remaining) ==='
  END as '';

SELECT 
  CASE WHEN (SELECT COUNT(*) FROM events WHERE dns_source = 'simulation') > 0 
  THEN 'Total remaining simulation events: ' || (SELECT COUNT(*) FROM events WHERE dns_source = 'simulation')
  ELSE ''
  END as '';

SELECT '' as '';
SELECT 'By network segment (test data):' as info;
SELECT network_segment, COUNT(*) as events, ROUND(AVG(anomaly_score), 2) as avg_score 
FROM events 
WHERE dns_source = 'simulation' 
GROUP BY network_segment 
ORDER BY events DESC;

SELECT '' as '';
SELECT 'Top vendors in test data + avg score:' as info;
SELECT COALESCE(device_vendor, 'Unknown') as vendor, COUNT(*) as events, ROUND(AVG(anomaly_score), 2) as avg_score 
FROM events 
WHERE dns_source = 'simulation' 
GROUP BY device_vendor 
ORDER BY events DESC 
LIMIT 8;

SELECT '' as '';
SELECT 'High-score test events (for reference):' as '';
SELECT domain, device_vendor, network_segment, ROUND(anomaly_score,2) as score, tags 
FROM events 
WHERE dns_source = 'simulation' AND anomaly_score > 0.3 
ORDER BY anomaly_score DESC 
LIMIT 5;

SELECT '(Note: High scores here are mostly from intentional test scenarios. The guardrails are designed to keep benign traffic from real devices low.)' as note;

SELECT '' as '';
SELECT 'Recent guardrails effectiveness (test data):' as info;
SELECT 'Ubiquiti test events: ' || COUNT(*) || ' (avg score ' || ROUND(AVG(anomaly_score),2) || ')' 
FROM events WHERE dns_source = 'simulation' AND (device_vendor LIKE '%ubiquiti%' OR device_vendor LIKE '%ubnt%');

SELECT 'Sonos test events: ' || COUNT(*) || ' (avg score ' || ROUND(AVG(anomaly_score),2) || ')' 
FROM events WHERE dns_source = 'simulation' AND device_vendor LIKE '%sonos%';

SELECT 'Samsung/SmartThings test events: ' || COUNT(*) || ' (avg score ' || ROUND(AVG(anomaly_score),2) || ')' 
FROM events WHERE dns_source = 'simulation' AND (device_vendor LIKE '%samsung%' OR device_vendor LIKE '%smartthings%');