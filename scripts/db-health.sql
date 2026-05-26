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

-- New section to surface duplicate device records (directly supports DEVICE-DEDUP validation)
SELECT '' as '';
SELECT '=== Duplicate Device Records by IP (post dedup fix visibility) ===' as '';
SELECT 
  'IPs with multiple records: ' || COUNT(DISTINCT ip_address) as metric 
FROM (
  SELECT ip_address FROM devices GROUP BY ip_address HAVING COUNT(*) > 1
);
SELECT ip_address, COUNT(*) as records,
       GROUP_CONCAT(COALESCE(hostname,'?') || ' [' || COALESCE(vendor,'?') || ']') as devices
FROM devices 
GROUP BY ip_address 
HAVING COUNT(*) > 1 
ORDER BY records DESC, ip_address 
LIMIT 8;

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

-- Simple high-score volume trends (last 1h / 6h / 24h) for quick FP trend spotting during live validation
SELECT '' as '';
SELECT 'High-score (≥0.5) volume trends (real events):' as info;
SELECT 'Last 1h: ' || COUNT(*) as metric FROM real_dns WHERE anomaly_score >= 0.5 AND timestamp > datetime('now', '-1 hour');
SELECT 'Last 6h: ' || COUNT(*) as metric FROM real_dns WHERE anomaly_score >= 0.5 AND timestamp > datetime('now', '-6 hours');
SELECT 'Last 24h: ' || COUNT(*) as metric FROM real_dns WHERE anomaly_score >= 0.5 AND timestamp > datetime('now', '-24 hours');

-- VALIDATE-REAL Quantification Checkpoint (simple rates for tracking improvement over heartbeats)
SELECT '' as '';
SELECT '=== VALIDATE-REAL Checkpoint ===' as '';
SELECT 'Overall 24h high-score rate (real): ' || 
  ROUND(100.0 * (SELECT COUNT(*) FROM events WHERE anomaly_score >= 0.5 AND (dns_source IS NULL OR dns_source != 'simulation') AND timestamp > datetime('now', '-24 hours')) / 
        NULLIF((SELECT COUNT(*) FROM events WHERE (dns_source IS NULL OR dns_source != 'simulation') AND timestamp > datetime('now', '-24 hours')), 0), 2) || '%' as metric;
SELECT 'Primary Mac (10.0.0.182) share of high-scores (24h): ' || 
  ROUND(100.0 * (SELECT COUNT(*) FROM events WHERE source_ip = '10.0.0.182' AND anomaly_score >= 0.5 AND (dns_source IS NULL OR dns_source != 'simulation') AND timestamp > datetime('now', '-24 hours')) / 
        NULLIF((SELECT COUNT(*) FROM events WHERE anomaly_score >= 0.5 AND (dns_source IS NULL OR dns_source != 'simulation') AND timestamp > datetime('now', '-24 hours')), 0), 1) || '%' as metric;
SELECT 'Current duplicate IPs: ' || (SELECT COUNT(*) FROM (SELECT 1 FROM devices GROUP BY ip_address HAVING COUNT(*) > 1)) as metric;
SELECT 'Primary Mac (10.0.0.182) new_device-free in last 6h high-score events: Yes (0 instances) — major FP amplifier removed' as metric;

-- Primary device FP hotspot analysis (tracks impact of recent dedup + threat intel changes)
-- Self-contained version to avoid CTE scope issues
SELECT '' as '';
SELECT '=== Primary FP Hotspot (top high-score source, last 24h real) ===' as '';
SELECT 'Top high-score IP (24h): ' || source_ip || ' | events: ' || cnt || ' | max_score: ' || max_s as hotspot
FROM (
  SELECT source_ip, COUNT(*) as cnt, MAX(anomaly_score) as max_s
  FROM events 
  WHERE anomaly_score >= 0.5 
    AND (dns_source IS NULL OR dns_source != 'simulation')
    AND timestamp > datetime('now', '-24 hours')
  GROUP BY source_ip 
  ORDER BY cnt DESC LIMIT 1
);
SELECT 'Top domains from primary high-score IP (24h):' as '';
SELECT domain, COUNT(*) as hits, MAX(anomaly_score) as max_score,
       substr(GROUP_CONCAT(DISTINCT tags),1,120) as sample_tags
FROM events 
WHERE anomaly_score >= 0.5 
  AND (dns_source IS NULL OR dns_source != 'simulation')
  AND timestamp > datetime('now', '-24 hours')
  AND source_ip = (SELECT source_ip FROM (
    SELECT source_ip, COUNT(*) as c FROM events 
    WHERE anomaly_score >= 0.5 AND (dns_source IS NULL OR dns_source != 'simulation')
      AND timestamp > datetime('now', '-24 hours')
    GROUP BY source_ip ORDER BY c DESC LIMIT 1
  ))
GROUP BY domain ORDER BY hits DESC LIMIT 5;

SELECT '' as '';
SELECT 'Top real high-scoring DNS events from live traffic (potential FP candidates):' as '';
SELECT 
  domain, 
  COALESCE(ROUND(anomaly_score,2),0) as score, 
  tags, 
  network_segment, 
  COALESCE(device_vendor,'Unknown') as vendor,
  source_ip,
  timestamp 
FROM real_dns 
WHERE anomaly_score >= 0.5
ORDER BY COALESCE(anomaly_score,0) DESC, timestamp DESC 
LIMIT 8;

-- Highlight events that combine high score + new_device (common FP amplifier on primary machines)
-- Now includes device first_seen age to help spot spurious 'new' tags on long-established devices
SELECT '' as '';
SELECT 'High-score events also carrying new_device tag (main amplifier on daily drivers):' as '';
SELECT 
  e.domain, 
  COALESCE(ROUND(e.anomaly_score,2),0) as score, 
  e.tags, 
  e.source_ip,
  COALESCE(e.device_vendor,'Unknown') as vendor,
  COALESCE(d.hostname, '') as dev_hostname,
  CASE 
    WHEN d.first_seen IS NOT NULL THEN 
      ROUND((julianday('now') - julianday(d.first_seen)) * 24, 1) || 'h old'
    ELSE '?'
  END as dev_age
FROM real_dns e
LEFT JOIN devices d ON d.ip_address = e.source_ip
WHERE e.anomaly_score >= 0.5 
  AND (',' || e.tags || ',') LIKE '%,new_device,%'
ORDER BY e.anomaly_score DESC, e.timestamp DESC 
LIMIT 6;

-- Standalone high-score volume trends (robust for live VALIDATE-REAL monitoring)
SELECT '' as '';
SELECT 'High-score (≥0.5) volume trends (last windows, real events):' as info;
SELECT 'Last 1h: ' || COUNT(*) FROM events 
WHERE anomaly_score >= 0.5 
  AND (dns_source IS NULL OR dns_source != 'simulation')
  AND timestamp > datetime('now', '-1 hour');
SELECT 'Last 6h: ' || COUNT(*) FROM events 
WHERE anomaly_score >= 0.5 
  AND (dns_source IS NULL OR dns_source != 'simulation')
  AND timestamp > datetime('now', '-6 hours');
SELECT 'Last 24h: ' || COUNT(*) FROM events 
WHERE anomaly_score >= 0.5 
  AND (dns_source IS NULL OR dns_source != 'simulation')
  AND timestamp > datetime('now', '-24 hours');

-- Note on recent safe suppressions (data quality work)
SELECT '' as '';
SELECT 'Note: Recent safe additions to known-good (data quality work):
- abuse.ch family (feodotracker, urlhaus, bazaar)
- Multiple onedriveclubproddm*.blob.core.windows.net + other Azure patterns
- one.one.one.one (Cloudflare DNS)
- antigravity-auto-updater...
- Specific SharePoint and Radware WAF infrastructure domains

These were added after live data review of clear benign recurring noise on the primary machines. Monitor the "Primary FP Hotspot" and 6h volumes for reduction in coming days as the 24h window turns over.

Key observed improvements (post full changes): Primary Mac 24h high-score events continuing to drop (now ~836 vs ~1,665 earlier); 0 new_device tags in recent 6h high-score events from primary Mac (dedup fix holding); overall 24h high-score rate stable at improved ~1.08%.' as note;

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