-- SNR Validation Seed Data
-- Three explicit risk tiers for testing detection scoring, device context boosts,
-- threat descriptions, grouping, context filters, quick suppression, and overall signal-to-noise.
-- Run via: docker cp scripts/seed-snr-validation.sql vedetta-backend:/tmp/seed.sql && docker compose exec backend sqlite3 /data/vedetta.db < /tmp/seed.sql

-- Clean any previous simulation rows for repeatable runs
DELETE FROM events WHERE source_hash LIKE 'sim-%' OR domain LIKE 'fp-%' OR domain LIKE 'mid-%' OR domain LIKE 'high-%';

-- ============================================================
-- TIER 1: false_positive (benign, known-good, low score < 0.3)
-- Expected: low anomaly_score, no risky tags, easily suppressed by known-good or quick buttons
-- ============================================================
INSERT INTO events (event_id, timestamp, event_type, source_hash, source_ip, domain, query_type, resolved_ip, blocked, anomaly_score, tags, device_vendor, network_segment, dns_source, threat_desc, metadata, acknowledged) VALUES
('sim-fp-001', datetime('now', '-12 minutes'), 'dns_query', 'sim-macbook-pro', '192.0.2.42', 'fp-update.apple.com', 'A', '17.253.0.1', 0, 0.09, '["dns_query"]', 'Apple', 'default', 'local', 'DNS query to known Apple update/telemetry domain (excluded from DGA/Beaconing)', '{"device_context":{"boosts":[]}}', 0),
('sim-fp-002', datetime('now', '-11 minutes'), 'dns_query', 'sim-macbook-pro', '192.0.2.42', 'fp-telemetry.google.com', 'A', '142.250.80.14', 0, 0.07, '["dns_query"]', 'Apple', 'default', 'local', 'DNS query to known Google telemetry (conservative single-signal cap + known-good exclusion)', '{"device_context":{"boosts":[]}}', 0),
('sim-fp-003', datetime('now', '-10 minutes'), 'dns_query', 'sim-windows-laptop', '192.0.2.55', 'fp-ms-update.windows.com', 'A', '13.107.0.1', 0, 0.11, '["dns_query"]', 'Dell', 'default', 'local', 'Normal Microsoft/Windows update traffic from trusted device', '{"device_context":{"boosts":[]}}', 0);

-- ============================================================
-- TIER 2: mid_warning (moderately suspicious: new_device or IoT + public DNS)
-- Uses representative public vendor names in a fully synthetic context
-- Expected: scores ~0.35-0.55, context tags visible, device_context boosts shown in UI
-- ============================================================
INSERT INTO events (event_id, timestamp, event_type, source_hash, source_ip, domain, query_type, resolved_ip, blocked, anomaly_score, tags, device_vendor, network_segment, dns_source, threat_desc, metadata, acknowledged) VALUES
('sim-mid-001', datetime('now', '-9 minutes'), 'dns_query', 'sim-new-esp32', '192.0.2.201', 'mid-iot-checkin.example', 'A', '1.1.1.1', 0, 0.44, '["dns_query","new_device_context","iot_context","public_dns"]', 'Espressif', 'iot', 'public', 'New IoT device (first seen <48h) on iot segment using public DNS resolver (device context boosts applied)', '{"device_context":{"boosts":[{"reason":"new_device (<48h) +0.15","delta":0.15},{"reason":"iot_segment +0.12","delta":0.12},{"reason":"public_dns_from_high_risk +0.12","delta":0.12}]}}', 0),
('sim-mid-002', datetime('now', '-8 minutes'), 'dns_query', 'sim-new-esp32', '192.0.2.201', 'mid-iot-telemetry.example', 'A', '8.8.8.8', 0, 0.39, '["dns_query","new_device_context","iot_context"]', 'Philips Lighting BV', 'iot', 'public', 'Synthetic new Philips Hue-like device on an IoT segment performing repeated lookups (moderate risk + context)', '{"device_context":{"boosts":[{"reason":"new_device (<48h) +0.15","delta":0.15},{"reason":"iot_segment +0.12","delta":0.12}]}}', 0);

-- ============================================================
-- TIER 3: high_threat (clearly malicious patterns + very_new_device + risky context)
-- Uses representative public IoT vendor names so boosts and suppression can be validated with synthetic rows
-- Expected: scores >0.65-0.80, red very_new_device tag, strong device context boosts, clear threat_desc
-- ============================================================
INSERT INTO events (event_id, timestamp, event_type, source_hash, source_ip, domain, query_type, resolved_ip, blocked, anomaly_score, tags, device_vendor, network_segment, dns_source, threat_desc, metadata, acknowledged) VALUES
('sim-high-001', datetime('now', '-7 minutes'), 'dns_query', 'sim-guest-laptop', '192.0.2.150', 'high-dga-x7k9p2m4q8w3z1v6b5n0.com', 'A', '203.0.113.77', 0, 0.81, '["dns_query","dga","very_new_device","new_device_context","guest"]', 'Unknown', 'guest', 'local', 'High-entropy DGA-like domain from very new guest device (device context boosts + DGA detector)', '{"device_context":{"boosts":[{"reason":"very_new_device (<1h) +0.10","delta":0.10},{"reason":"new_device (<48h) +0.15","delta":0.15},{"reason":"guest_segment +0.12","delta":0.12}]}}', 0),
('sim-high-002', datetime('now', '-6 minutes'), 'dns_query', 'sim-iot-cam', '192.0.2.210', 'high-rebind-192-168-1-1.attacker.example', 'A', '192.168.1.1', 0, 0.73, '["dns_query","dns_rebinding","very_new_device","new_device_context","iot_context"]', 'LIFX', 'iot', 'local', 'Synthetic DNS rebinding attempt targeting a very new LIFX device on iot (high-risk rebinding + context boost +0.25)', '{"device_context":{"boosts":[{"reason":"rebinding to high-risk device +0.25","delta":0.25},{"reason":"very_new_device (<1h) +0.10","delta":0.10},{"reason":"iot_segment +0.12","delta":0.12}]}}', 0),
('sim-high-003', datetime('now', '-5 minutes'), 'dns_query', 'sim-guest-laptop', '192.0.2.150', 'high-tunnel-longsubdomain-abc123def456ghi789.suspicious-cdn.example', 'TXT', '198.51.100.23', 0, 0.68, '["dns_query","dns_tunneling","new_device_context","guest"]', 'Unknown', 'guest', 'local', 'Long subdomain + high-entropy tunneling pattern from guest segment', '{"device_context":{"boosts":[{"reason":"new_device (<48h) +0.15","delta":0.15},{"reason":"guest_segment +0.12","delta":0.12}]}}', 0);

-- Quick count for verification
SELECT 'SNR seed complete. Tier counts:' as info;
SELECT 
  CASE 
    WHEN anomaly_score < 0.3 THEN 'false_positive'
    WHEN anomaly_score < 0.6 THEN 'mid_warning'
    ELSE 'high_threat'
  END as tier,
  COUNT(*) as count,
  ROUND(AVG(anomaly_score),2) as avg_score
FROM events 
WHERE source_hash LIKE 'sim-%'
GROUP BY tier
ORDER BY avg_score;
