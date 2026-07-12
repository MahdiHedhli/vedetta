import { useCallback, useEffect, useRef, useState } from 'react';
import {
  fetchAuthSession,
  fetchActiveFindings,
  fetchDetectionHealth,
  fetchFindingDetail,
  fetchFindingStats,
  fetchResolvedFindings,
  fetchSuppressedFindings,
  FINDINGS_MAX_LIMIT,
  FINDINGS_PAGE_SIZE,
  patchFindingStatus,
  RESOLVED_FINDINGS_PAGE_SIZE,
  SUPPRESSED_FINDINGS_PAGE_SIZE,
  suppressFinding as postFindingSuppression,
  unsuppressFinding as deleteFindingSuppression,
} from './api';

const initialState = {
  phase: 'loading',
  findings: [],
  activeFindings: [],
  suppressedFindings: [],
  resolvedFindings: [],
  stats: null,
  health: null,
  total: 0,
  activeTotal: 0,
  suppressedTotal: 0,
  resolvedTotal: 0,
  activeLimit: 0,
  suppressedLimit: 0,
  resolvedLimit: 0,
  queueLoading: { active: false, suppressed: false, resolved: false },
  queueAtCap: { active: false, suppressed: false, resolved: false },
  queueErrors: { active: null, suppressed: null, resolved: null },
  session: null,
  canAdmin: false,
  auxiliaryErrors: {},
  healthError: null,
  error: null,
  refreshing: false,
};

const HEALTH_PHASES = new Set(['healthy', 'initializing', 'stale', 'error', 'unauthorized']);
const HEALTH_SEVERITY = {
  healthy: 0,
  initializing: 1,
  stale: 2,
  error: 3,
  unauthorized: 4,
};

function normalizeHealthActor(actor = {}, kind) {
  return {
    ...actor,
    name: actor.name || actor.display_name || actor.source_id || actor.feed_id || 'Source',
    state: String(actor.state || actor.status || 'initializing').toLowerCase(),
    event_count: kind === 'source' ? (actor.event_count ?? actor.item_count) : actor.event_count,
  };
}

function normalizeHealth(health = {}) {
  return {
    ...health,
    state: String(health.state || health.status || '').toLowerCase(),
    sources: Array.isArray(health.sources) ? health.sources.map((actor) => normalizeHealthActor(actor, 'source')) : [],
    feeds: Array.isArray(health.feeds) ? health.feeds.map((actor) => normalizeHealthActor(actor, 'feed')) : [],
  };
}

function normalizeFinding(finding = {}) {
  const device = finding.device || {};
  return {
    ...finding,
    status: finding.status || finding.finding_status || 'open',
    current_priority: finding.current_priority || finding.priority || 'low',
    primary_observable_type: finding.primary_observable_type || finding.observable_type || '',
    primary_observable: finding.primary_observable || finding.observable_value || '',
    device_name: finding.device_name || finding.display_name || device.display_name || device.friendly_name || '',
    canonical_device_id: finding.canonical_device_id || device.canonical_device_id || device.device_id || finding.device_id || '',
  };
}

function healthPhase(health, findings) {
  const sources = Array.isArray(health?.sources) ? health.sources : [];
  const feeds = Array.isArray(health?.feeds) ? health.feeds : [];
  const declared = String(health?.state || '').toLowerCase();
  if (declared === 'error' || declared === 'unauthorized') return declared;
  // A healthy empty screen requires evidence from both halves of detection.
  // Missing/malformed actor collections are initialization, never reassurance.
  if (sources.length === 0 || feeds.length === 0) return 'initializing';

  const states = [declared, ...sources.map((item) => item.state), ...feeds.map((item) => item.state)]
    .filter((state) => HEALTH_PHASES.has(state));
  if (states.length !== 1 + sources.length + feeds.length) return 'initializing';
  const worst = states.reduce((current, state) =>
    HEALTH_SEVERITY[state] > HEALTH_SEVERITY[current] ? state : current, 'healthy');
  return worst === 'healthy' && findings.length === 0 ? 'healthy-empty' : worst;
}

function errorPhase(error) {
  return error?.status === 401 || error?.status === 403 ? 'unauthorized' : 'error';
}

function findingList(response) {
  if (Array.isArray(response)) return response;
  return Array.isArray(response?.findings) ? response.findings : [];
}

function uniqueFindings(...groups) {
  const seen = new Set();
  return groups.flat().filter((finding) => {
    if (!finding?.finding_id || seen.has(finding.finding_id)) return false;
    seen.add(finding.finding_id);
    return true;
  });
}

function queueForFinding(finding) {
  if (finding?.status === 'resolved') return 'resolved';
  if (finding?.disposition === 'suppressed') return 'suppressed';
  return 'active';
}

const QUEUE_FIELDS = {
  active: { items: 'activeFindings', limit: 'activeLimit', total: 'activeTotal', pageSize: FINDINGS_PAGE_SIZE },
  suppressed: { items: 'suppressedFindings', limit: 'suppressedLimit', total: 'suppressedTotal', pageSize: SUPPRESSED_FINDINGS_PAGE_SIZE },
  resolved: { items: 'resolvedFindings', limit: 'resolvedLimit', total: 'resolvedTotal', pageSize: RESOLVED_FINDINGS_PAGE_SIZE },
};
const QUEUES = Object.keys(QUEUE_FIELDS);

function queueFetcher(queue, limit) {
  if (queue === 'active') return fetchActiveFindings(limit);
  if (queue === 'suppressed') return fetchSuppressedFindings(limit);
  if (queue === 'resolved') return fetchResolvedFindings(limit);
  throw new Error(`Unknown findings queue: ${queue}`);
}

function queueLimit(queue, state, reset) {
  const fields = QUEUE_FIELDS[queue];
  if (reset) return fields.pageSize;
  return Math.min(FINDINGS_MAX_LIMIT, Math.max(fields.pageSize, Number(state[fields.limit] || fields.pageSize)));
}

function relocateFinding(current, patch) {
  if (!patch?.finding_id) return current;
  let previous = null;
  let previousQueue = '';
  for (const [queue, fields] of Object.entries(QUEUE_FIELDS)) {
    const match = current[fields.items].find((finding) => finding.finding_id === patch.finding_id);
    if (match) {
      previous = match;
      previousQueue = queue;
      break;
    }
  }
  const updated = normalizeFinding({ ...(previous || {}), ...patch });
  const nextQueue = queueForFinding(updated);
  const next = { ...current };
  for (const fields of Object.values(QUEUE_FIELDS)) {
    next[fields.items] = current[fields.items].filter((finding) => finding.finding_id !== updated.finding_id);
  }
  next[QUEUE_FIELDS[nextQueue].items] = [updated, ...next[QUEUE_FIELDS[nextQueue].items]];
  if (previousQueue && previousQueue !== nextQueue) {
    next[QUEUE_FIELDS[previousQueue].total] = Math.max(0, Number(current[QUEUE_FIELDS[previousQueue].total] || 0) - 1);
    next[QUEUE_FIELDS[nextQueue].total] = Number(current[QUEUE_FIELDS[nextQueue].total] || 0) + 1;
  } else if (!previousQueue) {
    next[QUEUE_FIELDS[nextQueue].total] = Math.max(Number(current[QUEUE_FIELDS[nextQueue].total] || 0), next[QUEUE_FIELDS[nextQueue].items].length);
  }
  next.findings = uniqueFindings(next.activeFindings, next.suppressedFindings, next.resolvedFindings);
  next.total = Number(next.activeTotal || 0) + Number(next.suppressedTotal || 0) + Number(next.resolvedTotal || 0);
  return next;
}

function settledError(result) {
  return result.status === 'rejected' ? result.reason : null;
}

export function useFindings({ pollMs = 10_000, refreshKey = '' } = {}) {
  const [state, setState] = useState(initialState);
  const mounted = useRef(true);
  const requestSequence = useRef(0);
  const stateRef = useRef(initialState);
  const queueGenerations = useRef({ active: 0, suppressed: 0, resolved: 0 });
  const loadMoreInFlight = useRef({ active: false, suppressed: false, resolved: false });
  stateRef.current = state;

  const invalidateQueueRequests = useCallback(() => {
    QUEUES.forEach((queue) => { queueGenerations.current[queue] += 1; });
  }, []);

  const refresh = useCallback(async ({ quiet = false, resetPages = false } = {}) => {
    if (!mounted.current) return;
    const requestID = ++requestSequence.current;
    const snapshot = stateRef.current;
    setState((current) => ({
      ...current,
      phase: current.health === null && current.findings.length === 0 ? 'loading' : current.phase,
      refreshing: !quiet,
      error: null,
    }));

    try {
      const plans = {};
      const queueRequests = QUEUES.map((queue) => {
        if (loadMoreInFlight.current[queue]) {
          plans[queue] = { skipped: true, generation: queueGenerations.current[queue] };
          return Promise.resolve(null);
        }
        const generation = ++queueGenerations.current[queue];
        const limit = queueLimit(queue, snapshot, resetPages);
        plans[queue] = { skipped: false, generation, limit };
        return queueFetcher(queue, limit);
      });
      const [activeResult, suppressedResult, resolvedResult, statsResult, healthResult, sessionResult] = await Promise.allSettled([
        ...queueRequests,
        fetchFindingStats(),
        fetchDetectionHealth(),
        fetchAuthSession(),
      ]);
      if (!mounted.current || requestID !== requestSequence.current) return;
      const session = sessionResult.status === 'fulfilled' ? sessionResult.value : null;
      const isFresh = (queue) => !plans[queue].skipped &&
        plans[queue].generation === queueGenerations.current[queue];
      if (isFresh('active') && activeResult.status === 'rejected') {
        setState((current) => ({
          ...current,
          phase: errorPhase(activeResult.reason),
          error: activeResult.reason,
          session,
          canAdmin: session?.can_admin === true,
          auxiliaryErrors: {
            suppressed: isFresh('suppressed') ? settledError(suppressedResult) : current.auxiliaryErrors.suppressed,
            resolved: isFresh('resolved') ? settledError(resolvedResult) : current.auxiliaryErrors.resolved,
            stats: settledError(statsResult),
            health: settledError(healthResult), session: settledError(sessionResult),
          },
          queueErrors: {
            ...current.queueErrors,
            active: activeResult.reason,
            suppressed: isFresh('suppressed') ? settledError(suppressedResult) : current.queueErrors.suppressed,
            resolved: isFresh('resolved') ? settledError(resolvedResult) : current.queueErrors.resolved,
          },
          refreshing: false,
        }));
        return;
      }

      const activeResponse = isFresh('active') && activeResult.status === 'fulfilled' ? activeResult.value : null;
      const suppressedResponse = isFresh('suppressed') && suppressedResult.status === 'fulfilled' ? suppressedResult.value : null;
      const resolvedResponse = isFresh('resolved') && resolvedResult.status === 'fulfilled' ? resolvedResult.value : null;
      const normalizedHealth = healthResult.status === 'fulfilled' ? normalizeHealth(healthResult.value) : null;
      setState((current) => {
        const nextActive = activeResponse
          ? findingList(activeResponse).map(normalizeFinding)
          : current.activeFindings;
        const nextSuppressed = suppressedResponse
          ? findingList(suppressedResponse).map(normalizeFinding)
          : current.suppressedFindings;
        const nextResolved = resolvedResponse
          ? findingList(resolvedResponse).map(normalizeFinding)
          : current.resolvedFindings;
        const activeTotal = activeResponse
          ? Number(activeResponse.total ?? nextActive.length)
          : Number(current.activeTotal || 0);
        const suppressedTotal = suppressedResponse
          ? Number(suppressedResponse.total ?? nextSuppressed.length)
          : Number(current.suppressedTotal || 0);
        const resolvedTotal = resolvedResponse
          ? Number(resolvedResponse.total ?? nextResolved.length)
          : Number(current.resolvedTotal || 0);
        const activeLimit = activeResponse ? Number(activeResponse.limit ?? plans.active.limit) : current.activeLimit;
        const suppressedLimit = suppressedResponse ? Number(suppressedResponse.limit ?? plans.suppressed.limit) : current.suppressedLimit;
        const resolvedLimit = resolvedResponse ? Number(resolvedResponse.limit ?? plans.resolved.limit) : current.resolvedLimit;
        let phase = 'health-error';
        if (normalizedHealth) {
          phase = healthPhase(normalizedHealth, nextActive);
          if (phase === 'error') phase = 'health-error';
          if (phase === 'unauthorized') phase = 'health-unauthorized';
        }
        const nextFindings = uniqueFindings(nextActive, nextSuppressed, nextResolved);
        return {
          ...current,
          phase,
          findings: nextFindings,
          activeFindings: nextActive,
          suppressedFindings: nextSuppressed,
          resolvedFindings: nextResolved,
          stats: statsResult.status === 'fulfilled' ? (statsResult.value || {}) : null,
          health: normalizedHealth,
          total: activeTotal + suppressedTotal + resolvedTotal,
          activeTotal,
          suppressedTotal,
          resolvedTotal,
          activeLimit,
          suppressedLimit,
          resolvedLimit,
          queueAtCap: {
            active: activeResponse ? activeLimit >= FINDINGS_MAX_LIMIT && nextActive.length < activeTotal : current.queueAtCap.active,
            suppressed: suppressedResponse ? suppressedLimit >= FINDINGS_MAX_LIMIT && nextSuppressed.length < suppressedTotal : current.queueAtCap.suppressed,
            resolved: resolvedResponse ? resolvedLimit >= FINDINGS_MAX_LIMIT && nextResolved.length < resolvedTotal : current.queueAtCap.resolved,
          },
          session,
          canAdmin: session?.can_admin === true,
          error: null,
          healthError: settledError(healthResult),
          auxiliaryErrors: {
            suppressed: isFresh('suppressed') ? settledError(suppressedResult) : current.auxiliaryErrors.suppressed,
            resolved: isFresh('resolved') ? settledError(resolvedResult) : current.auxiliaryErrors.resolved,
            stats: settledError(statsResult),
            health: settledError(healthResult), session: settledError(sessionResult),
          },
          queueErrors: {
            ...current.queueErrors,
            active: activeResponse ? null : current.queueErrors.active,
            suppressed: isFresh('suppressed') ? settledError(suppressedResult) : current.queueErrors.suppressed,
            resolved: isFresh('resolved') ? settledError(resolvedResult) : current.queueErrors.resolved,
          },
          refreshing: false,
        };
      });
    } catch (error) {
      if (!mounted.current || requestID !== requestSequence.current) return;
      setState((current) => ({
        ...current,
        phase: errorPhase(error),
        error,
        session: null,
        canAdmin: false,
        refreshing: false,
      }));
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    invalidateQueueRequests();
    QUEUES.forEach((queue) => { loadMoreInFlight.current[queue] = false; });
    setState(initialState);
    refresh({ resetPages: true });
    const timer = pollMs > 0 ? window.setInterval(() => refresh({ quiet: true }), pollMs) : null;
    return () => {
      mounted.current = false;
      requestSequence.current += 1;
      invalidateQueueRequests();
      QUEUES.forEach((queue) => { loadMoreInFlight.current[queue] = false; });
      if (timer) window.clearInterval(timer);
    };
  }, [invalidateQueueRequests, pollMs, refresh, refreshKey]);

  const loadDetail = useCallback(async (findingID, options) => {
    const response = await fetchFindingDetail(findingID, options);
    if (response?.finding) return { ...response, finding: normalizeFinding(response.finding) };
    return normalizeFinding(response);
  }, []);

  const updateStatus = useCallback(async (findingID, status, reason) => {
    const response = await patchFindingStatus(findingID, status, reason);
    const updated = normalizeFinding(response?.finding || response);
    if (updated?.finding_id) {
      invalidateQueueRequests();
      setState((current) => relocateFinding(current, updated));
    }
    return updated;
  }, [invalidateQueueRequests]);

  const loadMore = useCallback(async (queue) => {
    const fields = QUEUE_FIELDS[queue];
    if (!fields) throw new Error(`Unknown findings queue: ${queue}`);
    const snapshot = stateRef.current;
    const items = snapshot[fields.items];
    const total = Number(snapshot[fields.total] || 0);
    if (loadMoreInFlight.current[queue] || snapshot.queueAtCap[queue] || items.length >= total) return;
    const currentLimit = queueLimit(queue, snapshot, false);
    const nextLimit = Math.min(FINDINGS_MAX_LIMIT, currentLimit + fields.pageSize);
    if (nextLimit <= currentLimit) return;
    loadMoreInFlight.current[queue] = true;
    const generation = ++queueGenerations.current[queue];
    setState((current) => ({
      ...current,
      queueLoading: { ...current.queueLoading, [queue]: true },
      queueErrors: { ...current.queueErrors, [queue]: null },
    }));
    try {
      const response = await queueFetcher(queue, nextLimit);
      if (!mounted.current || generation !== queueGenerations.current[queue]) return;
      const incoming = findingList(response).map(normalizeFinding);
      setState((current) => {
        const currentFields = QUEUE_FIELDS[queue];
        const responseLimit = Number(response?.limit ?? nextLimit);
        const responseTotal = Number(response?.total ?? incoming.length);
        const next = {
          ...current,
          [currentFields.items]: incoming,
          [currentFields.limit]: responseLimit,
          [currentFields.total]: responseTotal,
          queueAtCap: {
            ...current.queueAtCap,
            [queue]: responseLimit >= FINDINGS_MAX_LIMIT && incoming.length < responseTotal,
          },
          queueErrors: { ...current.queueErrors, [queue]: null },
        };
        next.findings = uniqueFindings(next.activeFindings, next.suppressedFindings, next.resolvedFindings);
        next.total = Number(next.activeTotal || 0) + Number(next.suppressedTotal || 0) + Number(next.resolvedTotal || 0);
        return next;
      });
    } catch (error) {
      if (mounted.current && generation === queueGenerations.current[queue]) {
        setState((current) => ({
          ...current,
          queueErrors: { ...current.queueErrors, [queue]: error },
        }));
      }
    } finally {
      loadMoreInFlight.current[queue] = false;
      if (mounted.current) {
        setState((current) => ({
          ...current,
          queueLoading: { ...current.queueLoading, [queue]: false },
        }));
      }
    }
  }, []);

  const suppress = useCallback(async (findingID, reason) => {
    const response = await postFindingSuppression(findingID, reason);
    const ruleID = response?.rule?.rule_id || response?.suppression_rule?.rule_id || response?.rule_id || response?.suppression_rule_id;
    const updated = {
      ...(response?.finding || {}),
      finding_id: response?.finding?.finding_id || findingID,
      disposition: 'suppressed',
      suppression_rule_id: response?.finding?.suppression_rule_id || ruleID || '',
    };
    invalidateQueueRequests();
    setState((current) => relocateFinding(current, updated));
    return { ...response, finding: updated };
  }, [invalidateQueueRequests]);

  const unsuppress = useCallback(async (findingID, ruleID) => {
    const response = await deleteFindingSuppression(ruleID);
    const responseFinding = response?.finding || (Array.isArray(response?.findings)
      ? response.findings.find((finding) => finding.finding_id === findingID)
      : null);
    const updated = {
      ...(responseFinding || {}),
      finding_id: responseFinding?.finding_id || findingID,
      disposition: 'active',
      suppression_rule_id: '',
    };
    invalidateQueueRequests();
    setState((current) => relocateFinding(current, updated));
    return { ...response, finding: updated };
  }, [invalidateQueueRequests]);

  return { ...state, refresh, loadDetail, updateStatus, loadMore, suppress, unsuppress };
}
