import { beforeEach, describe, expect, it, vi } from 'vitest';
import { authFetchJSON } from '../lib/api';
import {
  fetchActiveFindings,
  fetchAuthSession,
  fetchFindingDetail,
  fetchResolvedFindings,
  fetchSuppressedFindings,
  FINDINGS_MAX_LIMIT,
  FINDINGS_PAGE_SIZE,
  RESOLVED_FINDINGS_PAGE_SIZE,
  suppressFinding,
  SUPPRESSED_FINDINGS_PAGE_SIZE,
  unsuppressFinding,
} from './api';

vi.mock('../lib/api', () => ({ authFetchJSON: vi.fn() }));

describe('findings API pagination', () => {
  beforeEach(() => authFetchJSON.mockReset());

  it('fetches actionable, suppressed, and resolved queues separately', async () => {
    const critical = { finding_id: 'critical-open', status: 'open', current_priority: 'critical' };
    const resolved = Array.from({ length: RESOLVED_FINDINGS_PAGE_SIZE }, (_, index) => ({
      finding_id: `resolved-${index}`,
      status: 'resolved',
    }));
    authFetchJSON
      .mockResolvedValueOnce({ findings: [critical], total: 1 })
      .mockResolvedValueOnce({ findings: [], total: 100 })
      .mockResolvedValueOnce({ findings: resolved, total: 100 });

    const activeResult = await fetchActiveFindings();
    const suppressedResult = await fetchSuppressedFindings();
    const resolvedResult = await fetchResolvedFindings();

    expect(authFetchJSON).toHaveBeenNthCalledWith(1, `/api/v1/findings?status=active&page=1&limit=${FINDINGS_PAGE_SIZE}&disposition=active`);
    expect(authFetchJSON).toHaveBeenNthCalledWith(2, `/api/v1/findings?status=active&page=1&limit=${SUPPRESSED_FINDINGS_PAGE_SIZE}&disposition=suppressed`);
    expect(authFetchJSON).toHaveBeenNthCalledWith(3, `/api/v1/findings?status=resolved&page=1&limit=${RESOLVED_FINDINGS_PAGE_SIZE}`);
    expect(activeResult.findings).toEqual([critical]);
    expect(suppressedResult.total).toBe(100);
    expect(resolvedResult.findings).toHaveLength(RESOLVED_FINDINGS_PAGE_SIZE);
    expect(resolvedResult.total).toBe(100);
  });

  it('sends independent evidence and event offsets for detail pagination', async () => {
    authFetchJSON.mockResolvedValue({ finding: { finding_id: 'finding/1' } });
    await fetchFindingDetail('finding/1', { evidenceOffset: 100, eventOffset: 200 });
    expect(authFetchJSON).toHaveBeenCalledWith(
      '/api/v1/findings/finding%2F1?evidence_limit=100&evidence_offset=100&event_limit=100&event_offset=200'
    );
  });

  it('requests independent page-one prefixes for every findings queue', async () => {
    authFetchJSON.mockResolvedValue({ findings: [], total: 101 });
    await fetchActiveFindings(200);
    await fetchSuppressedFindings(300);
    await fetchResolvedFindings(50);

    expect(authFetchJSON).toHaveBeenNthCalledWith(1, '/api/v1/findings?status=active&page=1&limit=200&disposition=active');
    expect(authFetchJSON).toHaveBeenNthCalledWith(2, '/api/v1/findings?status=active&page=1&limit=300&disposition=suppressed');
    expect(authFetchJSON).toHaveBeenNthCalledWith(3, '/api/v1/findings?status=resolved&page=1&limit=50');
  });

  it('bounds a findings prefix at the beta server cap', async () => {
    authFetchJSON.mockResolvedValue({ findings: [], total: FINDINGS_MAX_LIMIT + 1 });
    await fetchActiveFindings(FINDINGS_MAX_LIMIT + 1000);
    expect(authFetchJSON).toHaveBeenCalledWith(
      `/api/v1/findings?status=active&page=1&limit=${FINDINGS_MAX_LIMIT}&disposition=active`
    );
  });

  it('creates and removes typed finding suppression rules', async () => {
    authFetchJSON.mockResolvedValue({ rule: { rule_id: 'rule/1' } });
    await suppressFinding('finding/1', '  Expected maintenance traffic  ');
    await unsuppressFinding('rule/1');

    expect(authFetchJSON).toHaveBeenNthCalledWith(1, '/api/v1/findings/finding%2F1/suppress', {
      method: 'POST',
      body: { reason: 'Expected maintenance traffic' },
    });
    expect(authFetchJSON).toHaveBeenNthCalledWith(2, '/api/v1/finding-suppressions/rule%2F1', {
      method: 'DELETE',
    });
  });

  it('reads authoritative session capabilities', async () => {
    authFetchJSON.mockResolvedValue({ scope: 'read', authenticated: true, can_admin: false });
    await expect(fetchAuthSession()).resolves.toMatchObject({ can_admin: false });
    expect(authFetchJSON).toHaveBeenCalledWith('/api/v1/auth/session');
  });
});
