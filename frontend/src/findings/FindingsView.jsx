import React, { useEffect, useMemo, useRef, useState } from 'react';

const PRIORITY_STYLES = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  medium: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  low: 'bg-sky-500/20 text-sky-300 border-sky-500/40',
};

const STATE_STYLES = {
  healthy: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30',
  stale: 'text-amber-200 bg-amber-500/10 border-amber-500/30',
  error: 'text-red-200 bg-red-500/10 border-red-500/30',
  unauthorized: 'text-red-200 bg-red-500/10 border-red-500/30',
  initializing: 'text-sky-200 bg-sky-500/10 border-sky-500/30',
};

const LOW_IDENTITY_CONFIDENCE = 0.75;

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      return [value];
    }
  }
  return value && typeof value === 'object' ? [value] : [];
}

function asObject(value) {
  if (!value) return {};
  if (typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

function displayDate(value) {
  if (!value) return 'unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function displayName(device, finding) {
  return device?.display_name || device?.custom_name || device?.friendly_name || device?.hostname || finding.device_name ||
    (finding.device_id ? `Device ${finding.device_id.slice(0, 8)}` : 'Unidentified device');
}

function identityAttribution(device, ...findings) {
  // Finding-level confidence describes this event-to-asset association, so it
  // takes precedence as a complete attribution decision over the device's
  // mutable broader identity projection. Only fall back when the finding has
  // no attribution fields at all.
  const hasAttribution = (source) => source && (
    source.identity_confidence != null || source.identity?.confidence != null ||
    Object.prototype.hasOwnProperty.call(source, 'needs_identification') ||
    Object.prototype.hasOwnProperty.call(source, 'identity_conflict') ||
    source.identity_status != null || source.identity?.status != null
  );
  const findingSource = findings.find(hasAttribution);
  const sources = findingSource
    ? [findingSource]
    : [...findings.map((finding) => finding?.device), device].filter(Boolean);
  const confidence = sources
    .map((source) => source.identity_confidence ?? source.identity?.confidence)
    .map((value) => (value == null || value === '' ? null : Number(value)))
    .find((value) => Number.isFinite(value));
  const reviewStatuses = new Set(['unresolved', 'low_confidence', 'conflict', 'ambiguous']);
  const needsIdentification = sources.some((source) => {
    const rawConfidence = source.identity_confidence ?? source.identity?.confidence;
    const sourceConfidence = rawConfidence == null || rawConfidence === '' ? null : Number(rawConfidence);
    const status = String(source.identity_status || source.identity?.status || '').toLowerCase();
    return source.needs_identification === true || source.identity_conflict === true ||
      (Number.isFinite(sourceConfidence) && sourceConfidence < LOW_IDENTITY_CONFIDENCE) ||
      reviewStatuses.has(status);
  });
  return { confidence, needsIdentification };
}

function observableLabel(finding) {
  if (finding.observable_value) return finding.observable_value;
  if (typeof finding.primary_observable === 'string') return finding.primary_observable;
  return finding.primary_observable?.value || 'an observed threat indicator';
}

function outcomeLabel(finding) {
  const outcome = String(finding.outcome || '').toLowerCase();
  if (outcome === 'blocked') return 'Blocked';
  if (outcome === 'allowed') return 'Allowed';
  if (outcome === 'observed') return 'Observed';
  if (outcome === 'mixed') return 'Mixed outcome';
  if (finding.blocked === true) return 'Blocked';
  if (finding.blocked === false) return 'Observed';
  return 'Outcome unknown';
}

function outcomeCounts(finding) {
  const entries = [
    ['allowed', finding.allowed_count],
    ['blocked', finding.blocked_count],
    ['observed', finding.observed_count],
  ].filter(([, value]) => value != null);
  return entries.map(([label, value]) => `${Number(value || 0)} ${label}`).join(' · ');
}

function statusCounts(stats) {
  const priorities = stats?.open_by_priority || {};
  return {
    critical: Number(priorities.critical ?? stats?.open_critical ?? 0),
    high: Number(priorities.high ?? stats?.open_high ?? 0),
    affected: Number(stats?.affected_devices ?? stats?.affected_device_count ?? 0),
    resolved: Number(stats?.recently_resolved ?? stats?.recently_resolved_count ?? 0),
  };
}

function HealthBadge({ state }) {
  const normalized = String(state || 'initializing').toLowerCase();
  const style = STATE_STYLES[normalized] || STATE_STYLES.initializing;
  return <span className={`text-[11px] uppercase tracking-wide border rounded px-2 py-0.5 ${style}`}>{normalized}</span>;
}

export function DetectionStatePanel({ phase, health, error }) {
  const panels = {
    loading: {
      title: 'Loading findings and detection health…',
      body: 'Vedetta is checking collection sources and threat feeds.',
      style: STATE_STYLES.initializing,
    },
    'healthy-empty': {
      title: 'No actionable findings',
      body: 'Collection and threat feeds are reporting healthy. Raw events remain available for review.',
      style: STATE_STYLES.healthy,
    },
    initializing: {
      title: 'Collection is initializing',
      body: 'There is not enough current collection and feed data to determine finding state yet.',
      style: STATE_STYLES.initializing,
    },
    stale: {
      title: 'Detection data is stale',
      body: 'Some collection or threat-feed sources have not refreshed recently. Findings below may be incomplete.',
      style: STATE_STYLES.stale,
    },
    error: {
      title: 'Findings unavailable',
      body: 'The active findings queue could not be retrieved. Previously loaded data may be stale.',
      style: STATE_STYLES.error,
    },
    unauthorized: {
      title: 'Authentication required',
      body: 'Vedetta could not read findings or detection health with the current token.',
      style: STATE_STYLES.unauthorized,
    },
    'health-error': {
      title: 'Detection health is unavailable or degraded',
      body: 'Active findings loaded, but collection or threat-feed coverage is reporting errors or could not be checked.',
      style: STATE_STYLES.error,
    },
    'health-unauthorized': {
      title: 'A detection source needs authentication',
      body: 'Active findings loaded, but one or more collection or threat-feed sources could not authenticate.',
      style: STATE_STYLES.stale,
    },
  };
  const panel = panels[phase];
  if (!panel) return null;
  const badgeState = phase === 'error' || phase === 'health-error' ? 'error'
    : phase === 'unauthorized' || phase === 'health-unauthorized' ? 'unauthorized'
      : health?.state;

  return (
    <div role={['error', 'unauthorized', 'health-error', 'health-unauthorized'].includes(phase) ? 'alert' : 'status'} className={`border rounded-lg p-4 ${panel.style}`}>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-medium">{panel.title}</p>
          <p className="text-sm opacity-80 mt-1">{panel.body}</p>
          {error?.message && <p className="text-xs opacity-70 mt-2 font-mono">{error.message}</p>}
        </div>
        {badgeState && <HealthBadge state={badgeState} />}
      </div>
    </div>
  );
}

function AuxiliaryDataNotice({ errors }) {
  const labels = [];
  if (errors?.suppressed) labels.push('suppressed history');
  if (errors?.resolved) labels.push('resolved history');
  if (errors?.stats) labels.push('summary metrics');
  if (errors?.session) labels.push('admin capabilities');
  if (labels.length === 0) return null;
  return (
    <div className="border border-amber-500/30 bg-amber-500/10 text-amber-200 rounded-lg p-3 text-xs" role="status">
      Active findings are available, but {labels.join(', ')} could not be refreshed. Missing sections are not shown as zero.
    </div>
  );
}

function HealthCollection({ title, items, emptyText }) {
  return (
    <div className="bg-gray-950/50 border border-gray-800 rounded-lg p-3">
      <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">{title}</p>
      {items.length === 0 ? (
        <p className="text-xs text-gray-600">{emptyText}</p>
      ) : (
        <div className="space-y-2">
          {items.map((item, index) => (
            <div key={item.id || item.name || index} className="flex items-center justify-between gap-3 text-xs">
              <div className="min-w-0">
                <p className="text-gray-300 truncate">{item.name || item.display_name || item.source || item.id || 'Source'}</p>
                <p className="text-gray-600 truncate">
                  {item.last_success ? `Updated ${displayDate(item.last_success)}` : 'No successful refresh yet'}
                  {item.item_count != null ? ` · ${item.item_count} items` : ''}
                  {item.event_count != null ? ` · ${item.event_count} events` : ''}
                </p>
                {item.error && <p className="text-red-400/80 truncate mt-0.5">{item.error}</p>}
              </div>
              <HealthBadge state={item.state || item.status} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function DetectionHealthDetails({ health }) {
  if (!health) return null;
  const sources = Array.isArray(health.sources) ? health.sources : [];
  const feeds = Array.isArray(health.feeds) ? health.feeds : [];
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3" aria-label="Detection health details">
      <HealthCollection title="Collection sources" items={sources} emptyText="No collection source has reported yet." />
      <HealthCollection title="Threat feeds" items={feeds} emptyText="No threat feed has reported yet." />
    </div>
  );
}

function EvidenceList({ evidence }) {
  const entries = asArray(evidence);
  if (entries.length === 0) return <p className="text-sm text-gray-500">No structured evidence returned.</p>;

  return (
    <ul className="space-y-2" aria-label="Detection evidence">
      {entries.map((entry, index) => {
        if (typeof entry === 'string') return <li key={index} className="text-sm text-gray-300">{entry}</li>;
        const detector = entry.detector_name || entry.detector || 'Detector evidence';
        const observable = entry.observable_value || entry.value;
        const source = entry.threat_source || entry.threat_intel_source || entry.source;
        const isCommunity = String(source || '').trim().toLowerCase() === 'vedetta-community';
        const deviceContext = asObject(entry.device_context);
        const details = asObject(entry.details);
        return (
          <li key={entry.evidence_id || index} className="bg-gray-950/60 border border-gray-800 rounded p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-gray-200">{detector}</span>
              {entry.observable_type && <span className="text-[10px] uppercase text-gray-500">{entry.observable_type}</span>}
              {source && <span className={`text-[10px] px-1.5 py-0.5 rounded ${isCommunity ? 'bg-sky-500/10 text-sky-300' : 'bg-violet-500/10 text-violet-300'}`}>{source}</span>}
              {isCommunity && <span className="text-[10px] bg-sky-500/10 text-sky-300 px-1.5 py-0.5 rounded">advisory corroboration</span>}
            </div>
            {observable && <p className="text-xs font-mono text-gray-300 break-all mt-1">{observable}</p>}
            {(entry.rationale || entry.reason) && <p className="text-xs text-gray-400 mt-1">{entry.rationale || entry.reason}</p>}
            {isCommunity && <p className="text-xs text-sky-300/80 mt-1">Community evidence is advisory and corroborating only; it does not drive finding priority.</p>}
            <DeviceContextSummary context={deviceContext} />
            <div className="flex flex-wrap gap-3 text-[10px] text-gray-600 mt-2">
              {entry.event_id && <span>event <span className="font-mono">{entry.event_id}</span></span>}
              {entry.category && <span>category {entry.category}</span>}
              {entry.outcome && <span>outcome {entry.outcome}</span>}
              {entry.source_confidence != null && <span>confidence {entry.source_confidence}</span>}
              {!isCommunity && entry.score_contribution != null && <span>score +{Number(entry.score_contribution).toFixed(2)}</span>}
              {entry.feed_freshness && <span>feed refreshed {displayDate(entry.feed_freshness)}</span>}
              {entry.feed_stale && <span className="text-amber-400">feed stale</span>}
              {entry.created_at && <span>recorded {displayDate(entry.created_at)}</span>}
            </div>
            {Array.isArray(details.feed_tags) && details.feed_tags.length > 0 && <p className="text-[10px] text-gray-600 mt-1">feed tags: {details.feed_tags.join(', ')}</p>}
          </li>
        );
      })}
    </ul>
  );
}

function DeviceContextSummary({ context }) {
  if (!context || Object.keys(context).length === 0) return null;
  const values = [
    ['Type', context.device_type],
    ['Model', context.model],
    ['Segment', context.segment],
    ['Risk', [context.risk_category, context.risk_model].filter(Boolean).join(' · ')],
    ['Identity', context.identity_confidence != null ? `${Math.round(Number(context.identity_confidence) * 100)}%${context.identity_status ? ` · ${context.identity_status}` : ''}` : context.identity_status],
  ].filter(([, value]) => value);
  if (context.eol_risk) values.push(['Lifecycle', 'End-of-life / elevated risk']);
  return (
    <div className="flex flex-wrap gap-1.5 mt-2" aria-label="Device context">
      {values.map(([label, value]) => (
        <span key={label} className={`text-[10px] rounded px-1.5 py-0.5 ${label === 'Lifecycle' ? 'bg-red-500/10 text-red-300' : 'bg-gray-800 text-gray-400'}`}>{label}: {value}</span>
      ))}
    </div>
  );
}

function SupportingEvents({ events }) {
  const entries = asArray(events);
  if (entries.length === 0) return null;
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Supporting raw events</p>
      <ul className="space-y-1" aria-label="Supporting raw events">
        {entries.map((event, index) => (
          <li key={event.event_id || index} className="text-xs text-gray-400 font-mono bg-gray-950/60 rounded px-2 py-1.5">
            <div>
              {event.event_id ? `${event.event_id} · ` : ''}{displayDate(event.timestamp || event.created_at)} · {event.event_type || event.type || 'event'}
              {event.domain ? ` · ${event.domain}` : ''}
              {event.destination_ip ? ` · ${event.destination_ip}` : event.resolved_ip ? ` · ${event.resolved_ip}` : ''}
            </div>
            <div className="text-[10px] text-gray-600 mt-1">
              origin {event.origin || 'legacy/unknown'}
              {event.dns_source ? ` · DNS source ${event.dns_source}` : ''}
              {event.sensor_id ? ` · sensor ${event.sensor_id}` : ''}
              {event.device_id ? ` · device ${event.device_id}` : ' · unresolved device'}
              {event.identity_confidence != null ? ` · identity ${Math.round(Number(event.identity_confidence) * 100)}%` : ''}
              {event.identity_reason ? ` (${event.identity_reason})` : ''}
              {event.disposition ? ` · ${event.disposition}` : ''}
              {event.outcome ? ` · outcome ${event.outcome}` : event.blocked ? ' · outcome blocked' : ''}
              {event.match_type && event.matched_indicator ? ` · ${event.match_type} match ${event.matched_indicator}` : ''}
              {event.suppression_rule_id ? ` · suppression ${event.suppression_rule_id}` : ''}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function StatusHistory({ entries }) {
  const history = asArray(entries);
  if (history.length === 0) return null;
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Status history</p>
      <ul className="space-y-1">
        {history.map((entry, index) => (
          <li key={entry.history_id || index} className="text-xs text-gray-400">
            {displayDate(entry.changed_at)} · {entry.from_status || 'created'} → {entry.to_status}
            {entry.reason ? ` · ${entry.reason}` : ''}
            {entry.actor ? ` · ${entry.actor}` : ''}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function FindingCard({
  finding,
  device,
  onNavigateDevice,
  onLoadDetail,
  onUpdateStatus,
  onSuppress,
  onUnsuppress,
  canAdmin,
}) {
  const [expanded, setExpanded] = useState(false);
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState('');
  const [detailLoading, setDetailLoading] = useState(false);
  const [pageLoading, setPageLoading] = useState('');
  const [pageErrors, setPageErrors] = useState({ evidence: '', events: '' });
  const [detailOffsets, setDetailOffsets] = useState({ evidence: 0, events: 0 });
  const [editingStatus, setEditingStatus] = useState(false);
  const [nextStatus, setNextStatus] = useState(finding.status || 'open');
  const [reason, setReason] = useState('');
  const [statusError, setStatusError] = useState('');
  const [statusSaving, setStatusSaving] = useState(false);
  const [editingSuppression, setEditingSuppression] = useState(false);
  const [suppressionReason, setSuppressionReason] = useState('');
  const [suppressionError, setSuppressionError] = useState('');
  const [suppressionSaving, setSuppressionSaving] = useState(false);
  const headlineVersion = `${finding.updated_at || ''}|${finding.last_event_id || ''}|${finding.occurrence_count || 0}|${finding.status || ''}`;
  const previousHeadlineVersion = useRef(headlineVersion);

  const priority = String(finding.current_priority || finding.priority || 'medium').toLowerCase();
  const outcome = outcomeLabel(finding);
  const isBlocked = outcome === 'Blocked';
  const deviceName = displayName(device, finding);
  const occurrenceCount = Number(finding.occurrence_count ?? finding.count ?? 1);
  const outcomeCountText = outcomeCounts(finding);
  const findingDetail = detail?.finding || detail || finding;
  const evidence = detail?.evidence ?? findingDetail.evidence ?? finding.evidence;
  const events = detail?.supporting_events ?? detail?.events ?? findingDetail.supporting_events;
  const history = detail?.status_history ?? findingDetail.status_history;
  const canonicalDeviceID = findingDetail.canonical_device_id || finding.canonical_device_id || finding.device_id;
  const evidenceReturned = asArray(evidence).length;
  const eventsReturned = asArray(events).length;
  const evidenceTotal = Number(detail?.evidence_total ?? evidenceReturned);
  const eventsTotal = Number(detail?.supporting_event_total ?? eventsReturned);
  const detailLoaded = detail !== null;
  const isSuppressed = finding.disposition === 'suppressed';
  const suppressionRuleID = finding.suppression_rule_id || findingDetail.suppression_rule_id;
  const attribution = identityAttribution(device, findingDetail, finding);
  const tentativeAttribution = Boolean(canonicalDeviceID && attribution.needsIdentification);
  const needsIdentification = !canonicalDeviceID || tentativeAttribution;

  const replaceDetail = (fresh) => {
    setDetail(fresh);
    setDetailOffsets({
      evidence: Number(fresh?.evidence_offset || 0) + asArray(fresh?.evidence).length,
      events: Number(fresh?.supporting_event_offset || 0) + asArray(fresh?.supporting_events).length,
    });
  };

  useEffect(() => {
    setNextStatus(finding.status || 'open');
    setDetail((current) => {
      if (!current) return current;
      if (current.finding) return { ...current, finding: { ...current.finding, ...finding } };
      return { ...current, ...finding };
    });
  }, [finding]);

  useEffect(() => {
    if (previousHeadlineVersion.current === headlineVersion) return;
    previousHeadlineVersion.current = headlineVersion;
    if (!expanded || !detailLoaded || !onLoadDetail) return;
    let cancelled = false;
    setDetailLoading(true);
    onLoadDetail(finding.finding_id)
      .then((fresh) => {
        if (!cancelled) {
          replaceDetail(fresh);
          setDetailError('');
        }
      })
      .catch((cause) => {
        if (!cancelled) setDetailError(cause?.message || 'Finding changed, but refreshed evidence could not be loaded.');
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => { cancelled = true; };
  }, [detailLoaded, expanded, finding.finding_id, headlineVersion, onLoadDetail]);

  const toggleDetail = async () => {
    const opening = !expanded;
    setExpanded(opening);
    if (!opening || detail || !onLoadDetail) return;
    setDetailLoading(true);
    setDetailError('');
    try {
      replaceDetail(await onLoadDetail(finding.finding_id));
    } catch (error) {
      setDetailError(error?.message || 'Unable to load finding evidence.');
    } finally {
      setDetailLoading(false);
    }
  };

  const loadMore = async (kind) => {
    if (!onLoadDetail || pageLoading) return;
    setPageLoading(kind);
    setPageErrors((current) => ({ ...current, [kind]: '' }));
    try {
      const options = kind === 'evidence'
        ? { evidenceOffset: detailOffsets.evidence, eventOffset: 0 }
        : { evidenceOffset: 0, eventOffset: detailOffsets.events };
      const page = await onLoadDetail(finding.finding_id, options);
      const pageEntries = asArray(kind === 'evidence' ? page?.evidence : page?.supporting_events);
      const responseOffset = Number(kind === 'evidence'
        ? (page?.evidence_offset ?? options.evidenceOffset)
        : (page?.supporting_event_offset ?? options.eventOffset));
      setDetailOffsets((current) => ({
        ...current,
        [kind]: Math.max(current[kind], responseOffset + pageEntries.length),
      }));
      setDetail((current) => {
        const base = current || {};
        const key = kind === 'evidence' ? 'evidence_id' : 'event_id';
        const field = kind === 'evidence' ? 'evidence' : 'supporting_events';
        const existing = asArray(base[field]);
        const seen = new Set(existing.map((entry) => entry?.[key]).filter(Boolean));
        const appended = asArray(page?.[field]).filter((entry) => {
          const id = entry?.[key];
          if (id && seen.has(id)) return false;
          if (id) seen.add(id);
          return true;
        });
        return {
          ...base,
          ...page,
          finding: { ...(base.finding || {}), ...(page?.finding || {}) },
          evidence: kind === 'evidence' ? [...existing, ...appended] : base.evidence,
          supporting_events: kind === 'events' ? [...existing, ...appended] : base.supporting_events,
          status_history: page?.status_history || base.status_history,
        };
      });
    } catch (error) {
      setPageErrors((current) => ({
        ...current,
        [kind]: error?.message || `Unable to load more ${kind === 'evidence' ? 'evidence' : 'supporting events'}.`,
      }));
    } finally {
      setPageLoading('');
    }
  };

  const saveStatus = async (event) => {
    event.preventDefault();
    if (nextStatus === 'resolved' && !reason.trim()) {
      setStatusError('A reason is required to resolve a finding.');
      return;
    }
    setStatusSaving(true);
    setStatusError('');
    try {
      const updated = await onUpdateStatus(finding.finding_id, nextStatus, reason);
      if (updated?.status) setNextStatus(updated.status);
      if (expanded && onLoadDetail) {
        try {
          replaceDetail(await onLoadDetail(finding.finding_id));
          setDetailError('');
        } catch (detailCause) {
          setDetailError(detailCause?.message || 'Status updated, but refreshed evidence could not be loaded.');
        }
      }
      setEditingStatus(false);
      setReason('');
    } catch (error) {
      setStatusError(error?.message || 'Unable to update finding status.');
    } finally {
      setStatusSaving(false);
    }
  };

  const saveSuppression = async (event) => {
    event.preventDefault();
    if (!suppressionReason.trim()) {
      setSuppressionError('A reason is required to suppress similar findings.');
      return;
    }
    setSuppressionSaving(true);
    setSuppressionError('');
    try {
      await onSuppress(finding.finding_id, suppressionReason);
      setEditingSuppression(false);
      setSuppressionReason('');
    } catch (error) {
      setSuppressionError(error?.message || 'Unable to suppress similar findings.');
    } finally {
      setSuppressionSaving(false);
    }
  };

  const removeSuppression = async () => {
    if (!suppressionRuleID || suppressionSaving) return;
    setSuppressionSaving(true);
    setSuppressionError('');
    try {
      await onUnsuppress(finding.finding_id, suppressionRuleID);
    } catch (error) {
      setSuppressionError(error?.message || 'Unable to remove this suppression rule.');
    } finally {
      setSuppressionSaving(false);
    }
  };

  return (
    <article className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden" data-finding-id={finding.finding_id}>
      <div className="p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className={`text-[11px] uppercase tracking-wide border rounded px-2 py-0.5 ${PRIORITY_STYLES[priority] || PRIORITY_STYLES.medium}`}>{priority}</span>
              <span className={`text-[11px] uppercase tracking-wide rounded px-2 py-0.5 ${isBlocked ? 'bg-emerald-500/15 text-emerald-300' : outcome === 'Allowed' ? 'bg-red-500/15 text-red-300' : 'bg-gray-700 text-gray-300'}`}>{outcome}</span>
              <span className="text-[11px] uppercase tracking-wide bg-gray-800 text-gray-400 rounded px-2 py-0.5">{finding.status || 'open'}</span>
              {needsIdentification && <span className="text-[11px] uppercase tracking-wide bg-amber-500/15 text-amber-300 rounded px-2 py-0.5">needs identification</span>}
              {finding.disposition === 'suppressed' && <span className="text-[11px] uppercase tracking-wide bg-violet-500/15 text-violet-300 rounded px-2 py-0.5">suppressed</span>}
            </div>
            <h3 className="text-lg font-medium text-white">
              {deviceName}{tentativeAttribution && (
                <span className="ml-1.5 text-sm font-normal text-amber-300">
                  (tentative{attribution.confidence != null ? `, ${Math.round(attribution.confidence * 100)}% identity confidence` : ''})
                </span>
              )} · {finding.category || finding.detector || 'Security finding'}
            </h3>
            <p className="text-sm text-gray-300 mt-1 break-words">
              {finding.reason || `${finding.detector || 'Vedetta'} detected ${observableLabel(finding)}.`}
            </p>
          </div>
          <div className="text-right text-xs text-gray-500 flex-shrink-0">
            <p>{occurrenceCount} occurrence{occurrenceCount === 1 ? '' : 's'}</p>
            {outcomeCountText && <p className="mt-1">{outcomeCountText}</p>}
            <p className="mt-1">{displayDate(finding.first_seen)} – {displayDate(finding.last_seen)}</p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
          <div className="bg-gray-950/50 rounded-lg p-3">
            <p className="text-xs uppercase tracking-wide text-gray-500">Primary observable</p>
            <p className="font-mono text-gray-200 mt-1 break-all">{observableLabel(finding)}</p>
            {(finding.primary_observable_type || finding.observable_type) && <p className="text-xs text-gray-600 mt-1">{finding.primary_observable_type || finding.observable_type}</p>}
          </div>
          <div className="bg-gray-950/50 rounded-lg p-3">
            <p className="text-xs uppercase tracking-wide text-gray-500">Recommended action</p>
            <p className="text-gray-200 mt-1">{finding.recommended_action || 'Review the supporting evidence and affected device.'}</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 mt-4 pt-4 border-t border-gray-800">
          {canonicalDeviceID && (
            <button type="button" onClick={() => onNavigateDevice?.(canonicalDeviceID)} className="text-sm text-amber-400 hover:text-amber-300">
              {tentativeAttribution ? 'View tentative device' : 'View device'}
            </button>
          )}
          <button type="button" onClick={toggleDetail} className="text-sm text-sky-400 hover:text-sky-300" aria-expanded={expanded}>
            {expanded ? 'Hide evidence' : 'View evidence'}
          </button>
          {canAdmin !== false && (
            <button type="button" onClick={() => setEditingStatus((value) => !value)} className="text-sm text-gray-300 hover:text-white">
              Update status
            </button>
          )}
          {canAdmin !== false && !isSuppressed && finding.status !== 'resolved' && onSuppress && (
            <button type="button" onClick={() => setEditingSuppression((value) => !value)} className="text-sm text-violet-300 hover:text-violet-200">
              Suppress similar
            </button>
          )}
          {canAdmin !== false && isSuppressed && suppressionRuleID && onUnsuppress && (
            <button type="button" disabled={suppressionSaving} onClick={removeSuppression} className="text-sm text-violet-300 hover:text-violet-200 disabled:text-gray-600">
              {suppressionSaving ? 'Removing suppression…' : 'Unsuppress'}
            </button>
          )}
          {finding.last_event_id && <span className="ml-auto text-[10px] text-gray-600 font-mono">last event {finding.last_event_id}</span>}
        </div>

        {editingSuppression && (
          <form onSubmit={saveSuppression} className="mt-4 bg-violet-500/5 border border-violet-500/20 rounded-lg p-3 space-y-3" aria-label="Suppress similar findings">
            <p className="text-xs text-gray-400">
              This creates a typed rule for this detector, observable, and affected asset. Evidence remains available, and resolution status is unchanged.
            </p>
            <label className="block text-xs text-gray-400">
              Suppression reason (required)
              <input value={suppressionReason} onChange={(event) => setSuppressionReason(event.target.value)} className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" placeholder="Why should future matching findings be quieted?" />
            </label>
            {suppressionError && <p role="alert" className="text-xs text-red-400">{suppressionError}</p>}
            <div className="flex justify-end">
              <button disabled={suppressionSaving} type="submit" className="bg-violet-400 hover:bg-violet-300 disabled:bg-gray-700 text-gray-950 px-3 py-1.5 rounded text-sm font-medium">
                {suppressionSaving ? 'Suppressing…' : 'Create suppression'}
              </button>
            </div>
          </form>
        )}

        {!editingSuppression && suppressionError && <p role="alert" className="mt-3 text-xs text-red-400">{suppressionError}</p>}

        {editingStatus && (
          <form onSubmit={saveStatus} className="mt-4 bg-gray-950/60 border border-gray-800 rounded-lg p-3 space-y-3" aria-label="Update finding status">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label className="text-xs text-gray-400">
                Status
                <select value={nextStatus} onChange={(event) => setNextStatus(event.target.value)} className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-2 py-2 text-sm text-gray-200">
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                </select>
              </label>
              <label className="text-xs text-gray-400 sm:col-span-2">
                Reason {nextStatus === 'resolved' ? '(required)' : '(optional)'}
                <input value={reason} onChange={(event) => setReason(event.target.value)} className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" placeholder="Describe the investigation or resolution" />
              </label>
            </div>
            {statusError && <p role="alert" className="text-xs text-red-400">{statusError}</p>}
            <div className="flex justify-end">
              <button disabled={statusSaving} type="submit" className="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 text-gray-950 px-3 py-1.5 rounded text-sm font-medium">
                {statusSaving ? 'Saving…' : 'Save status'}
              </button>
            </div>
          </form>
        )}
      </div>

      {expanded && (
        <div className="border-t border-gray-800 bg-gray-900/60 p-5 space-y-4">
          <p className="text-xs uppercase tracking-wide text-gray-500">Why Vedetta believes this</p>
          {detailLoading ? <p role="status" className="text-sm text-gray-400">Loading evidence…</p> : detailError ? <p role="alert" className="text-sm text-red-400">{detailError}</p> : <EvidenceList evidence={evidence} />}
          {!detailLoading && !detailError && evidenceTotal > evidenceReturned && (
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-xs text-amber-300">Showing the newest {evidenceReturned} of {evidenceTotal} evidence records.</p>
              <button type="button" disabled={Boolean(pageLoading)} onClick={() => loadMore('evidence')} className="text-xs text-sky-400 hover:text-sky-300 disabled:text-gray-600">
                {pageLoading === 'evidence' ? 'Loading…' : 'Load more evidence'}
              </button>
            </div>
          )}
          {pageErrors.evidence && <p role="alert" className="text-xs text-red-400">{pageErrors.evidence}</p>}
          {!detailLoading && !detailError && <SupportingEvents events={events} />}
          {!detailLoading && !detailError && eventsTotal > eventsReturned && (
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-xs text-amber-300">Showing the newest {eventsReturned} of {eventsTotal} supporting raw events.</p>
              <button type="button" disabled={Boolean(pageLoading)} onClick={() => loadMore('events')} className="text-xs text-sky-400 hover:text-sky-300 disabled:text-gray-600">
                {pageLoading === 'events' ? 'Loading…' : 'Load more events'}
              </button>
            </div>
          )}
          {pageErrors.events && <p role="alert" className="text-xs text-red-400">{pageErrors.events}</p>}
          {!detailLoading && !detailError && <StatusHistory entries={history} />}
        </div>
      )}
    </article>
  );
}

export function FindingsView({ state, devices = [], onNavigateDevice, canAdmin }) {
  const [queueFilter, setQueueFilter] = useState('actionable');
  const deviceByID = useMemo(() => new Map(devices.map((device) => [device.device_id, device])), [devices]);
  const findings = state.findings || [];
  const activeFindings = state.activeFindings || findings.filter((finding) => finding.status !== 'resolved' && finding.disposition !== 'suppressed');
  const suppressedFindings = state.suppressedFindings || findings.filter((finding) => finding.status !== 'resolved' && finding.disposition === 'suppressed');
  const resolvedFindings = state.resolvedFindings || findings.filter((finding) => finding.status === 'resolved');
  const allFindings = useMemo(() => {
    const seen = new Set();
    return [...activeFindings, ...suppressedFindings, ...resolvedFindings].filter((finding) => {
      if (!finding?.finding_id || seen.has(finding.finding_id)) return false;
      seen.add(finding.finding_id);
      return true;
    });
  }, [activeFindings, suppressedFindings, resolvedFindings]);
  const filtered = queueFilter === 'resolved' ? resolvedFindings
    : queueFilter === 'suppressed' ? suppressedFindings
      : queueFilter === 'actionable' ? activeFindings : allFindings;
  const queueKey = queueFilter === 'actionable' ? 'active' : queueFilter;
  const queueTotal = queueFilter === 'actionable' ? Number(state.activeTotal ?? activeFindings.length)
    : queueFilter === 'suppressed' ? Number(state.suppressedTotal ?? suppressedFindings.length)
      : queueFilter === 'resolved' ? Number(state.resolvedTotal ?? resolvedFindings.length) : allFindings.length;
  const queueLoading = Boolean(state.queueLoading?.[queueKey]);
  const queueError = state.queueErrors?.[queueKey];
  const allQueueProgress = [
    { key: 'active', label: 'actionable', loaded: activeFindings.length, total: Number(state.activeTotal ?? activeFindings.length), capped: Boolean(state.queueAtCap?.active) },
    { key: 'suppressed', label: 'suppressed', loaded: suppressedFindings.length, total: Number(state.suppressedTotal ?? suppressedFindings.length), capped: Boolean(state.queueAtCap?.suppressed) },
    { key: 'resolved', label: 'resolved', loaded: resolvedFindings.length, total: Number(state.resolvedTotal ?? resolvedFindings.length), capped: Boolean(state.queueAtCap?.resolved) },
  ];
  const incompleteAllQueues = allQueueProgress.filter((queue) => queue.loaded < queue.total && !queue.capped);
  const cappedAllQueues = allQueueProgress.filter((queue) => queue.capped);
  const counts = statusCounts(state.stats);
  const metricsAvailable = Boolean(state.stats) && !['loading', 'initializing', 'stale', 'error', 'unauthorized', 'health-error', 'health-unauthorized'].includes(state.phase);

  return (
    <section aria-label="Findings">
      <div className="flex flex-wrap items-start justify-between gap-4 mb-5">
        <div>
          <h2 className="text-2xl font-display">Actionable Findings</h2>
          <p className="text-sm text-gray-500 mt-1">Durable device-centered detections, with raw events preserved as evidence.</p>
        </div>
        <button type="button" onClick={() => state.refresh?.()} disabled={state.refreshing} className="text-sm bg-gray-800 hover:bg-gray-700 disabled:text-gray-600 text-gray-200 px-3 py-2 rounded-lg">
          {state.refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        <SummaryMetric label="Open critical" value={metricsAvailable ? counts.critical : '—'} danger={metricsAvailable && counts.critical > 0} />
        <SummaryMetric label="Open high" value={metricsAvailable ? counts.high : '—'} danger={metricsAvailable && counts.high > 0} />
        <SummaryMetric label="Affected assets / sources" value={metricsAvailable ? counts.affected : '—'} />
        <SummaryMetric label="Recently resolved" value={metricsAvailable ? counts.resolved : '—'} />
      </div>

      <div className="space-y-3 mb-5">
        <DetectionStatePanel phase={state.phase} health={state.health} error={state.healthError || state.error} />
        <AuxiliaryDataNotice errors={state.auxiliaryErrors} />
        <DetectionHealthDetails health={state.health} />
      </div>

      <div className="flex items-center gap-1 mb-4" role="group" aria-label="Finding status filter">
        {[
          ['actionable', 'Actionable'],
          ['suppressed', 'Suppressed'],
          ['resolved', 'Resolved'],
          ['all', 'All'],
        ].map(([value, label]) => (
          <button key={value} type="button" onClick={() => setQueueFilter(value)} className={`text-xs px-3 py-1.5 rounded ${queueFilter === value ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}>
            {label}
          </button>
        ))}
      </div>

      {queueFilter === 'resolved' && Number(state.resolvedTotal || 0) > filtered.length && (
        <p className="text-xs text-gray-500 mb-3">Showing the newest {filtered.length} of {state.resolvedTotal} resolved findings.</p>
      )}
      {queueFilter === 'actionable' && Number(state.activeTotal || 0) > filtered.length && (
        <p className="text-xs text-gray-500 mb-3">Showing the newest {filtered.length} of {state.activeTotal} actionable findings.</p>
      )}
      {queueFilter === 'suppressed' && Number(state.suppressedTotal || 0) > filtered.length && (
        <p className="text-xs text-gray-500 mb-3">Showing the newest {filtered.length} of {state.suppressedTotal} suppressed findings.</p>
      )}
      {queueFilter !== 'all' && state.queueAtCap?.[queueKey] && (
        <p className="text-xs text-amber-300 mb-3">This queue reached the 5,000-finding beta display limit. The newest findings remain available.</p>
      )}
      {queueFilter === 'all' && (incompleteAllQueues.length > 0 || cappedAllQueues.length > 0) && (
        <div className="border border-gray-800 bg-gray-900/50 rounded-lg p-3 mb-3" role="status">
          <p className="text-xs text-gray-400">
            All is the union of the independently loaded actionable, suppressed, and resolved queues. Load each queue to extend this combined view.
          </p>
          <div className="flex flex-wrap gap-2 mt-2">
            {incompleteAllQueues.map((queue) => (
              <button
                key={queue.key}
                type="button"
                disabled={Boolean(state.queueLoading?.[queue.key])}
                onClick={() => state.loadMore?.(queue.key)}
                className="text-xs bg-gray-800 hover:bg-gray-700 disabled:text-gray-600 text-gray-200 px-3 py-1.5 rounded"
              >
                {state.queueLoading?.[queue.key] ? 'Loading…' : `Load more ${queue.label} findings`}
              </button>
            ))}
          </div>
          {allQueueProgress.filter((queue) => state.queueErrors?.[queue.key]).map((queue) => (
            <p key={queue.key} role="alert" className="text-xs text-red-400 mt-2">
              More {queue.label} findings could not be loaded: {state.queueErrors[queue.key].message || 'request failed'}
            </p>
          ))}
          {cappedAllQueues.map((queue) => (
            <p key={`cap-${queue.key}`} className="text-xs text-amber-300 mt-2">
              The {queue.label} queue reached the 5,000-finding beta display limit.
            </p>
          ))}
        </div>
      )}
      {queueFilter !== 'all' && queueError && (
        <p role="alert" className="text-xs text-red-400 mb-3">More {queueFilter} findings could not be loaded: {queueError.message || 'request failed'}</p>
      )}

      {filtered.length > 0 ? (
        <div className="space-y-4">
          {filtered.map((finding) => (
            <FindingCard
              key={finding.finding_id}
              finding={finding}
              device={deviceByID.get(finding.canonical_device_id || finding.device_id) || deviceByID.get(finding.device_id)}
              onNavigateDevice={onNavigateDevice}
              onLoadDetail={state.loadDetail}
              onUpdateStatus={state.updateStatus}
              onSuppress={state.suppress}
              onUnsuppress={state.unsuppress}
              canAdmin={canAdmin}
            />
          ))}
          {queueFilter !== 'all' && filtered.length < queueTotal && !state.queueAtCap?.[queueKey] && (
            <div className="flex justify-center pt-2">
              <button type="button" disabled={queueLoading} onClick={() => state.loadMore?.(queueKey)} className="text-sm bg-gray-800 hover:bg-gray-700 disabled:text-gray-600 text-gray-200 px-4 py-2 rounded-lg">
                {queueLoading ? 'Loading…' : `Load more ${queueFilter} findings`}
              </button>
            </div>
          )}
        </div>
      ) : state.phase !== 'loading' && !(queueFilter === 'actionable' && state.phase === 'healthy-empty') && (
        <div className="border border-gray-800 rounded-lg p-8 text-center text-sm text-gray-500">
          No findings match this status filter. Detection health is shown above.
        </div>
      )}
    </section>
  );
}

function SummaryMetric({ label, value, danger = false }) {
  return (
    <div className={`bg-gray-900 border rounded-lg p-3 ${danger ? 'border-red-500/40' : 'border-gray-800'}`}>
      <p className="text-xs text-gray-500">{label}</p>
      <p className={`text-2xl font-display mt-1 ${danger ? 'text-red-300' : 'text-gray-100'}`}>{value}</p>
    </div>
  );
}

export function FindingsDashboardSummary({ state, onNavigate }) {
  const counts = statusCounts(state.stats);
  const unavailable = !state.stats || ['error', 'unauthorized', 'loading', 'stale', 'initializing', 'health-error', 'health-unauthorized'].includes(state.phase);
  const healthLabel = state.phase === 'healthy-empty' ? 'healthy' : state.phase === 'health-error' ? 'error' : state.phase === 'health-unauthorized' ? 'unauthorized' : state.phase;
  const healthSub = state.phase === 'error' ? 'Findings retrieval failed' : state.phase === 'health-error' ? 'Coverage health degraded' : state.phase === 'health-unauthorized' ? 'Source authentication required' : state.phase === 'unauthorized' ? 'Authentication required' : state.phase === 'stale' ? 'Review stale sources' : state.phase === 'initializing' || state.phase === 'loading' ? 'Initializing' : 'Collection and feeds current';
  return (
    <>
      <button type="button" onClick={onNavigate} className="text-left bg-gray-900 border border-gray-800 hover:border-gray-700 rounded-lg p-4 transition-colors">
        <p className="text-sm text-gray-400">Open critical / high</p>
        <p className={`text-2xl font-display mt-1 ${!unavailable && counts.critical + counts.high > 0 ? 'text-red-300' : 'text-gray-100'}`}>{unavailable ? '—' : counts.critical + counts.high}</p>
        <p className="text-xs text-gray-500 mt-1">Actionable findings</p>
      </button>
      <button type="button" onClick={onNavigate} className="text-left bg-gray-900 border border-gray-800 hover:border-gray-700 rounded-lg p-4 transition-colors">
        <p className="text-sm text-gray-400">Affected assets / sources</p>
        <p className="text-2xl font-display mt-1">{unavailable ? '—' : counts.affected}</p>
        <p className="text-xs text-gray-500 mt-1">With open findings</p>
      </button>
      <button type="button" onClick={onNavigate} className="text-left bg-gray-900 border border-gray-800 hover:border-gray-700 rounded-lg p-4 transition-colors">
        <p className="text-sm text-gray-400">Recently resolved</p>
        <p className="text-2xl font-display mt-1">{unavailable ? '—' : counts.resolved}</p>
        <p className="text-xs text-gray-500 mt-1">Current reporting window</p>
      </button>
      <button type="button" onClick={onNavigate} className={`text-left border rounded-lg p-4 transition-colors ${STATE_STYLES[healthLabel] || STATE_STYLES.initializing}`}>
        <p className="text-sm opacity-80">Detection health</p>
        <p className="text-lg font-display mt-1 capitalize">{healthLabel === 'healthy-empty' ? 'healthy' : healthLabel}</p>
        <p className="text-xs opacity-70 mt-1">{healthSub}</p>
      </button>
    </>
  );
}

export function FindingsWorkspace({ state, devices, onNavigateDevice, rawEventsView, canAdmin }) {
  const [tab, setTab] = useState('findings');
  return (
    <div>
      <div className="flex items-center gap-1 border-b border-gray-800 mb-6" role="tablist" aria-label="Threat view">
        <button type="button" role="tab" aria-selected={tab === 'findings'} onClick={() => setTab('findings')} className={`px-4 py-2.5 text-sm border-b-2 ${tab === 'findings' ? 'border-amber-400 text-white' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
          Findings
        </button>
        <button type="button" role="tab" aria-selected={tab === 'raw'} onClick={() => setTab('raw')} className={`px-4 py-2.5 text-sm border-b-2 ${tab === 'raw' ? 'border-amber-400 text-white' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
          Raw events
        </button>
      </div>
      {tab === 'findings' ? <FindingsView state={state} devices={devices} onNavigateDevice={onNavigateDevice} canAdmin={canAdmin} /> : rawEventsView}
    </div>
  );
}
