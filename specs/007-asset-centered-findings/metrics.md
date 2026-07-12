# Success Metrics: Asset-Centered Findings

The sprint persists the dimensions needed to measure identity coverage, finding
compression, lifecycle, suppression, feed contribution, and recommendation coverage.
The dashboard's `/api/v1/findings/stats` endpoint exposes current open priority counts,
affected assets/sources, and recently resolved findings. The compatibility JSON field is
named `affected_devices`, but it counts both canonical devices and unresolved fallback
source identities. The remaining beta metrics are local operator analytics and can be
calculated against Core's SQLite database without adding external telemetry.

From the repository's Compose directory, open the SQLite shell shipped in the Core
container, then paste the queries below:

```sh
docker compose exec backend sqlite3 /data/vedetta.db
```

Percentages use all retained local rows, so interpret them alongside the configured
retention window.

```sql
-- Event association and high-confidence association (>= 0.80).
SELECT COUNT(*) AS total_events,
       SUM(device_id IS NOT NULL AND device_id <> '') AS associated_events,
       ROUND(100.0 * SUM(device_id IS NOT NULL AND device_id <> '') /
             NULLIF(COUNT(*), 0), 1) AS associated_pct,
       SUM(device_id IS NOT NULL AND device_id <> '' AND identity_confidence >= 0.80)
         AS high_confidence_events,
       ROUND(100.0 * SUM(device_id IS NOT NULL AND device_id <> '' AND
                         identity_confidence >= 0.80) / NULLIF(COUNT(*), 0), 1)
         AS high_confidence_pct
FROM events;

-- Operator-detected duplicate records and incorrect-merge proxy. A split is an
-- exact audited undo of a prior merge, so split/merge is the beta error signal.
SELECT SUM(action_type = 'merge') AS operator_duplicate_merges,
       SUM(action_type = 'split') AS incorrect_merges_undone,
       ROUND(100.0 * SUM(action_type = 'split') /
             NULLIF(SUM(action_type = 'merge'), 0), 1) AS merge_undo_pct
FROM device_identity_actions;

-- Raw supporting-event compression into durable findings.
SELECT COUNT(*) AS finding_event_links,
       COUNT(DISTINCT finding_id) AS findings_with_events,
       ROUND(1.0 * COUNT(*) / NULLIF(COUNT(DISTINCT finding_id), 0), 2)
         AS supporting_events_per_finding
FROM finding_events;

-- Recurrence and suppression by detector.
SELECT COUNT(DISTINCT finding_id) AS findings_reopened
FROM finding_status_history
WHERE from_status = 'resolved' AND to_status = 'open';

SELECT detector, COUNT(*) AS findings,
       SUM(disposition = 'suppressed') AS suppressed,
       ROUND(100.0 * SUM(disposition = 'suppressed') /
             NULLIF(COUNT(*), 0), 1) AS suppressed_pct
FROM findings GROUP BY detector ORDER BY findings DESC;

-- Threat-source evidence and how often it is exact finding evidence. Community
-- evidence may be retained and linked when it corroborates trusted evidence, so a
-- non-zero community link count is valid. This query does not imply that community
-- evidence independently created or raised a finding; processor policy forbids that.
SELECT e.threat_source,
       COUNT(*) AS evidence_rows,
       COUNT(fe.evidence_id) AS finding_evidence_links
FROM event_detection_evidence e
LEFT JOIN finding_evidence fe ON fe.evidence_id = e.evidence_id
WHERE e.threat_source <> ''
GROUP BY e.threat_source ORDER BY evidence_rows DESC;

-- Findings that provide a concrete operator action.
SELECT COUNT(*) AS findings,
       SUM(TRIM(recommended_action) <> '') AS with_recommended_action,
       ROUND(100.0 * SUM(TRIM(recommended_action) <> '') /
             NULLIF(COUNT(*), 0), 1) AS recommended_action_pct
FROM findings;
```

Feed freshness, last success, item count, and error state are available from
`GET /api/v1/health/detection`. Current finding priority and affected-asset/source counts
are available from `GET /api/v1/findings/stats`; neither endpoint exports these metrics.
