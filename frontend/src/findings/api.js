import { authFetchJSON } from '../lib/api';

export const FINDINGS_PAGE_SIZE = 100;
export const SUPPRESSED_FINDINGS_PAGE_SIZE = 100;
export const RESOLVED_FINDINGS_PAGE_SIZE = 25;
export const FINDINGS_MAX_LIMIT = 5000;

function findingsPrefix(status, limit, disposition = '') {
  const boundedLimit = Math.min(FINDINGS_MAX_LIMIT, Math.max(1, Number(limit) || 1));
  const params = new URLSearchParams({ status, page: '1', limit: String(boundedLimit) });
  if (disposition) params.set('disposition', disposition);
  return authFetchJSON(`/api/v1/findings?${params.toString()}`);
}

// Active findings are the critical queue read. Auxiliary resolved-history
// failures must never erase this response in the UI.
export function fetchActiveFindings(limit = FINDINGS_PAGE_SIZE) {
  return findingsPrefix('active', limit, 'active');
}

export function fetchSuppressedFindings(limit = SUPPRESSED_FINDINGS_PAGE_SIZE) {
  return findingsPrefix('active', limit, 'suppressed');
}

export function fetchResolvedFindings(limit = RESOLVED_FINDINGS_PAGE_SIZE) {
  return findingsPrefix('resolved', limit);
}

export function fetchFindingStats() {
  return authFetchJSON('/api/v1/findings/stats');
}

export function fetchDetectionHealth() {
  return authFetchJSON('/api/v1/health/detection');
}

export function fetchAuthSession() {
  return authFetchJSON('/api/v1/auth/session');
}

export function fetchFindingDetail(findingID, {
  evidenceLimit = 100,
  evidenceOffset = 0,
  eventLimit = 100,
  eventOffset = 0,
} = {}) {
  const params = new URLSearchParams({
    evidence_limit: String(evidenceLimit),
    evidence_offset: String(evidenceOffset),
    event_limit: String(eventLimit),
    event_offset: String(eventOffset),
  });
  return authFetchJSON(`/api/v1/findings/${encodeURIComponent(findingID)}?${params.toString()}`);
}

export function patchFindingStatus(findingID, status, reason = '') {
  return authFetchJSON(`/api/v1/findings/${encodeURIComponent(findingID)}/status`, {
    method: 'PATCH',
    body: { status, reason: reason.trim() },
  });
}

export function suppressFinding(findingID, reason) {
  return authFetchJSON(`/api/v1/findings/${encodeURIComponent(findingID)}/suppress`, {
    method: 'POST',
    body: { reason: reason.trim() },
  });
}

export function unsuppressFinding(ruleID) {
  return authFetchJSON(`/api/v1/finding-suppressions/${encodeURIComponent(ruleID)}`, {
    method: 'DELETE',
  });
}
