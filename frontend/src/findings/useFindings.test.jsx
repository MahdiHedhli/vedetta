import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchActiveFindings,
  fetchAuthSession,
  fetchDetectionHealth,
  fetchFindingDetail,
  fetchFindingStats,
  fetchResolvedFindings,
  fetchSuppressedFindings,
  patchFindingStatus,
  suppressFinding,
  unsuppressFinding,
} from './api';
import { useFindings } from './useFindings';

vi.mock('./api', () => ({
  FINDINGS_MAX_LIMIT: 5000,
  FINDINGS_PAGE_SIZE: 100,
  SUPPRESSED_FINDINGS_PAGE_SIZE: 100,
  RESOLVED_FINDINGS_PAGE_SIZE: 25,
  fetchActiveFindings: vi.fn(),
  fetchAuthSession: vi.fn(),
  fetchDetectionHealth: vi.fn(),
  fetchFindingDetail: vi.fn(),
  fetchFindingStats: vi.fn(),
  fetchResolvedFindings: vi.fn(),
  fetchSuppressedFindings: vi.fn(),
  patchFindingStatus: vi.fn(),
  suppressFinding: vi.fn(),
  unsuppressFinding: vi.fn(),
}));

describe('useFindings', () => {
  beforeEach(() => {
    fetchAuthSession.mockResolvedValue({ scope: 'admin', authenticated: true, can_admin: true });
    fetchActiveFindings.mockResolvedValue({ findings: [], total: 0, page: 1, limit: 100 });
    fetchSuppressedFindings.mockResolvedValue({ findings: [], total: 0, page: 1, limit: 100 });
    fetchResolvedFindings.mockResolvedValue({ findings: [], total: 0, page: 1, limit: 25 });
    fetchFindingStats.mockResolvedValue({ open_by_priority: {}, affected_devices: 0, recently_resolved: 0 });
    fetchDetectionHealth.mockResolvedValue({
      state: 'healthy',
      sources: [{ source_id: 'sensor-1', display_name: 'LAN sensor', status: 'healthy', item_count: 3 }],
      feeds: [{ source_id: 'feed-1', display_name: 'IOC feed', status: 'healthy', item_count: 20 }],
    });
  });

  it('only calls an empty result healthy after the health endpoint succeeds', async () => {
    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    expect(result.current.phase).toBe('loading');
    await waitFor(() => expect(result.current.phase).toBe('healthy-empty'));
    expect(result.current.findings).toEqual([]);
    expect(result.current.health.state).toBe('healthy');
    expect(result.current.health.sources[0]).toMatchObject({ name: 'LAN sensor', state: 'healthy', event_count: 3 });
    expect(result.current.canAdmin).toBe(true);
  });

  it('uses the authoritative read session to disable admin actions', async () => {
    fetchAuthSession.mockResolvedValue({ scope: 'read', authenticated: true, can_admin: false });
    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('healthy-empty'));
    expect(result.current.session).toMatchObject({ scope: 'read', authenticated: true });
    expect(result.current.canAdmin).toBe(false);
  });

  it('uses the worst child health even when the aggregate claims healthy', async () => {
    fetchDetectionHealth.mockResolvedValue({
      state: 'healthy',
      sources: [{ display_name: 'Collector', status: 'error', error: 'parser stopped' }],
      feeds: [{ display_name: 'IOC feed', status: 'healthy', item_count: 20 }],
    });
    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('health-error'));
    expect(result.current.health.sources[0]).toMatchObject({ name: 'Collector', state: 'error' });
    expect(result.current.error).toBeNull();
  });

  it('does not call an actor-less healthy response a healthy empty network', async () => {
    fetchDetectionHealth.mockResolvedValue({ state: 'healthy', sources: [], feeds: [] });
    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('initializing'));
    expect(result.current.phase).not.toBe('healthy-empty');
  });

  it('maps an authorization failure to the explicit unauthorized state', async () => {
    const error = new Error('HTTP 401');
    error.status = 401;
    fetchActiveFindings.mockRejectedValue(error);

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('unauthorized'));
    expect(result.current.error).toBe(error);
    expect(result.current.phase).not.toBe('healthy-empty');
  });

  it('loads detail and updates a finding lifecycle through the server APIs', async () => {
    const finding = { finding_id: 'finding-1', status: 'open' };
    fetchActiveFindings.mockResolvedValue({ findings: [finding], total: 1 });
    fetchFindingDetail.mockResolvedValue({ finding, evidence: [{ detector: 'ioc_match' }] });
    patchFindingStatus.mockResolvedValue({ finding: { ...finding, status: 'investigating' } });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.findings).toHaveLength(1));

    await expect(result.current.loadDetail('finding-1')).resolves.toMatchObject({ finding });
    await act(() => result.current.updateStatus('finding-1', 'investigating', 'Reviewing firmware'));

    expect(fetchFindingDetail).toHaveBeenCalledWith('finding-1', undefined);
    expect(patchFindingStatus).toHaveBeenCalledWith('finding-1', 'investigating', 'Reviewing firmware');
  });

  it('treats resolved-only history as a healthy empty active queue', async () => {
    const resolved = { finding_id: 'resolved-1', status: 'resolved' };
    fetchResolvedFindings.mockResolvedValue({ findings: [resolved], total: 1 });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('healthy-empty'));

    expect(result.current.findings).toEqual([expect.objectContaining(resolved)]);
    expect(result.current.activeTotal).toBe(0);
    expect(result.current.resolvedTotal).toBe(1);
  });

  it('treats a suppressed-only active response as no actionable findings', async () => {
    fetchSuppressedFindings.mockResolvedValue({
      findings: [{ finding_id: 'suppressed-1', status: 'open', disposition: 'suppressed' }],
      total: 1,
    });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('healthy-empty'));
    expect(result.current.findings).toEqual([
      expect.objectContaining({ finding_id: 'suppressed-1', disposition: 'suppressed' }),
    ]);
    expect(result.current.activeTotal).toBe(0);
    expect(result.current.suppressedTotal).toBe(1);
  });

  it('cannot let a full suppressed page crowd an actionable finding out of the queue', async () => {
    const actionable = { finding_id: 'high-actionable', status: 'open', disposition: 'active', current_priority: 'high' };
    fetchActiveFindings.mockResolvedValue({ findings: [actionable], total: 1 });
    fetchSuppressedFindings.mockResolvedValue({
      findings: Array.from({ length: 100 }, (_, index) => ({
        finding_id: `suppressed-${index}`, status: 'open', disposition: 'suppressed', current_priority: 'critical',
      })),
      total: 100,
    });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('healthy'));
    expect(result.current.findings).toContainEqual(expect.objectContaining(actionable));
    expect(result.current.activeTotal).toBe(1);
    expect(result.current.suppressedTotal).toBe(100);
  });

  it('uses a fixed prefix horizon and recovers a displaced boundary on the next load', async () => {
    const oldFindings = Array.from({ length: 300 }, (_, index) => ({
      finding_id: `active-${index + 1}`, status: 'open', disposition: 'active',
    }));
    let mutated = false;
    fetchActiveFindings.mockImplementation((limit = 100) => {
      // Net-neutral mutation: one new top finding while an older finding moves
      // to another queue. Total does not reveal the boundary shift.
      const ordered = mutated
        ? [{ finding_id: 'active-new', status: 'open', disposition: 'active' }, ...oldFindings.filter((finding) => finding.finding_id !== 'active-250')]
        : oldFindings;
      return Promise.resolve({ findings: ordered.slice(0, limit), total: ordered.length, page: 1, limit });
    });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.activeFindings).toHaveLength(100));
    await act(async () => result.current.loadMore('active'));
    expect(result.current.activeFindings).toHaveLength(200);
    expect(result.current.activeFindings.at(-1)).toMatchObject({ finding_id: 'active-200' });
    expect(fetchActiveFindings).toHaveBeenCalledWith(200);

    mutated = true;
    await act(async () => result.current.refresh({ quiet: true }));
    expect(fetchActiveFindings).toHaveBeenLastCalledWith(200);
    expect(result.current.activeFindings[0]).toMatchObject({ finding_id: 'active-new' });
    expect(result.current.activeFindings).not.toContainEqual(expect.objectContaining({ finding_id: 'active-200' }));
    expect(result.current.activeFindings).not.toContainEqual(expect.objectContaining({ finding_id: 'active-250' }));
    expect(result.current.activeFindings).toHaveLength(200);
    expect(result.current.activeLimit).toBe(200);

    await act(async () => result.current.loadMore('active'));
    expect(fetchActiveFindings).toHaveBeenLastCalledWith(300);
    expect(result.current.activeFindings).toContainEqual(expect.objectContaining({ finding_id: 'active-200' }));
    expect(result.current.activeFindings).not.toContainEqual(expect.objectContaining({ finding_id: 'active-250' }));
    expect(result.current.activeFindings).toHaveLength(300);
    expect(result.current.activeLimit).toBe(300);
  });

  it('does not auto-expand the loaded prefix when the queue total grows', async () => {
    const original = Array.from({ length: 300 }, (_, index) => ({
      finding_id: `active-${index + 1}`, status: 'open', disposition: 'active',
    }));
    let grown = false;
    fetchActiveFindings.mockImplementation((limit = 100) => {
      const ordered = grown
        ? [{ finding_id: 'active-new', status: 'open', disposition: 'active' }, ...original]
        : original;
      return Promise.resolve({ findings: ordered.slice(0, limit), total: ordered.length, page: 1, limit });
    });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.activeFindings).toHaveLength(100));
    await act(async () => result.current.loadMore('active'));
    expect(result.current.activeLimit).toBe(200);

    grown = true;
    await act(async () => result.current.refresh({ quiet: true }));
    expect(fetchActiveFindings).toHaveBeenLastCalledWith(200);
    expect(result.current.activeLimit).toBe(200);
    expect(result.current.activeFindings).toHaveLength(200);
  });

  it('replaces a loaded prefix so transitioned findings are not retained as stale', async () => {
    const active = Array.from({ length: 200 }, (_, index) => ({
      finding_id: `active-${index + 1}`, status: 'open', disposition: 'active',
    }));
    let transitioned = false;
    fetchActiveFindings.mockImplementation((limit = 100) => {
      const ordered = transitioned ? active.filter((finding) => finding.finding_id !== 'active-150') : active;
      return Promise.resolve({ findings: ordered.slice(0, limit), total: ordered.length, page: 1, limit });
    });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.activeFindings).toHaveLength(100));
    await act(async () => result.current.loadMore('active'));
    expect(result.current.activeFindings).toContainEqual(expect.objectContaining({ finding_id: 'active-150' }));

    transitioned = true;
    await act(async () => result.current.refresh({ quiet: true }));
    expect(result.current.activeFindings).not.toContainEqual(expect.objectContaining({ finding_id: 'active-150' }));
    expect(result.current.activeFindings).toHaveLength(199);
  });

  it('expands active, suppressed, and resolved prefix horizons independently', async () => {
    const prefix = (queue, status, disposition, firstLimit) => vi.fn((limit = firstLimit) => Promise.resolve({
      findings: Array.from({ length: limit > firstLimit ? 2 : 1 }, (_, index) => ({
        finding_id: `${queue}-prefix-${index + 1}`, status, disposition,
      })),
      total: 2,
      page: 1,
      limit,
    }));
    fetchActiveFindings.mockImplementation(prefix('active', 'open', 'active', 100));
    fetchSuppressedFindings.mockImplementation(prefix('suppressed', 'open', 'suppressed', 100));
    fetchResolvedFindings.mockImplementation(prefix('resolved', 'resolved', undefined, 25));

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.findings).toHaveLength(3));

    await act(async () => result.current.loadMore('suppressed'));
    expect(result.current.suppressedFindings).toHaveLength(2);
    expect(result.current.activeFindings).toHaveLength(1);
    expect(result.current.resolvedFindings).toHaveLength(1);

    await act(async () => result.current.loadMore('resolved'));
    expect(result.current.resolvedFindings).toHaveLength(2);
    expect(result.current.activeFindings).toHaveLength(1);

    await act(async () => result.current.loadMore('active'));
    expect(result.current.activeFindings).toHaveLength(2);
    expect(fetchSuppressedFindings).toHaveBeenCalledWith(200);
    expect(fetchResolvedFindings).toHaveBeenCalledWith(50);
    expect(fetchActiveFindings).toHaveBeenCalledWith(200);
  });

  it('does not let a stale refresh overwrite a later load-more prefix', async () => {
    const initial = Array.from({ length: 100 }, (_, index) => ({
      finding_id: `active-${index + 1}`, status: 'open', disposition: 'active',
    }));
    const expanded = Array.from({ length: 200 }, (_, index) => ({
      finding_id: `active-${index + 1}`, status: 'open', disposition: 'active',
    }));
    let resolveRefresh;
    let resolveLoadMore;
    const refreshResponse = new Promise((resolve) => { resolveRefresh = resolve; });
    const loadMoreResponse = new Promise((resolve) => { resolveLoadMore = resolve; });
    let mode = 'initial';
    fetchActiveFindings.mockImplementation((limit = 100) => {
      if (mode === 'refresh') {
        mode = 'load-more';
        return refreshResponse;
      }
      if (mode === 'load-more') return loadMoreResponse;
      return Promise.resolve({ findings: initial, total: 300, page: 1, limit });
    });

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.activeFindings).toHaveLength(100));
    mode = 'refresh';
    let refreshPromise;
    act(() => { refreshPromise = result.current.refresh({ quiet: true }); });
    await waitFor(() => expect(fetchActiveFindings).toHaveBeenLastCalledWith(100));

    let loadMorePromise;
    act(() => { loadMorePromise = result.current.loadMore('active'); });
    await waitFor(() => expect(fetchActiveFindings).toHaveBeenLastCalledWith(200));
    await act(async () => {
      resolveLoadMore({ findings: expanded, total: 300, page: 1, limit: 200 });
      await loadMorePromise;
    });
    expect(result.current.activeFindings).toHaveLength(200);
    expect(result.current.activeLimit).toBe(200);

    await act(async () => {
      resolveRefresh({ findings: initial, total: 300, page: 1, limit: 100 });
      await refreshPromise;
    });
    expect(result.current.activeFindings).toHaveLength(200);
    expect(result.current.activeLimit).toBe(200);
  });

  it('moves a finding between actionable and suppressed queues after rule mutations', async () => {
    const finding = { finding_id: 'finding-noisy', status: 'investigating', disposition: 'active', current_priority: 'high' };
    fetchActiveFindings.mockResolvedValue({ findings: [finding], total: 1 });
    suppressFinding.mockResolvedValue({ rule: { rule_id: 'rule-1' } });
    unsuppressFinding.mockResolvedValue({});

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.activeFindings).toHaveLength(1));
    await act(async () => result.current.suppress('finding-noisy', 'Known scanner'));
    expect(suppressFinding).toHaveBeenCalledWith('finding-noisy', 'Known scanner');
    expect(result.current.activeFindings).toHaveLength(0);
    expect(result.current.suppressedFindings).toContainEqual(expect.objectContaining({
      finding_id: 'finding-noisy', suppression_rule_id: 'rule-1', disposition: 'suppressed',
      status: 'investigating', current_priority: 'high',
    }));

    await act(async () => result.current.unsuppress('finding-noisy', 'rule-1'));
    expect(unsuppressFinding).toHaveBeenCalledWith('rule-1');
    expect(result.current.suppressedFindings).toHaveLength(0);
    expect(result.current.activeFindings).toContainEqual(expect.objectContaining({
      finding_id: 'finding-noisy', disposition: 'active', status: 'investigating', current_priority: 'high',
    }));
  });

  it('keeps active findings when auxiliary reads fail and never substitutes false zeros', async () => {
    const finding = { finding_id: 'finding-survives', status: 'open', current_priority: 'high' };
    fetchActiveFindings.mockResolvedValue({ findings: [finding], total: 1 });
    fetchResolvedFindings.mockRejectedValue(new Error('resolved failed'));
    fetchFindingStats.mockRejectedValue(new Error('stats failed'));
    fetchDetectionHealth.mockRejectedValue(new Error('health failed'));
    fetchAuthSession.mockRejectedValue(new Error('session failed'));

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('health-error'));

    expect(result.current.findings).toEqual([expect.objectContaining(finding)]);
    expect(result.current.stats).toBeNull();
    expect(result.current.canAdmin).toBe(false);
    expect(result.current.auxiliaryErrors).toMatchObject({
      suppressed: null,
      resolved: expect.any(Error),
      stats: expect.any(Error),
      health: expect.any(Error),
      session: expect.any(Error),
    });
  });

  it('keeps the actionable queue available when suppressed history fails', async () => {
    const finding = { finding_id: 'finding-actionable', status: 'open', disposition: 'active' };
    fetchActiveFindings.mockResolvedValue({ findings: [finding], total: 1 });
    fetchSuppressedFindings.mockRejectedValue(new Error('suppressed failed'));

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('healthy'));
    expect(result.current.findings).toEqual([expect.objectContaining(finding)]);
    expect(result.current.auxiliaryErrors.suppressed).toBeInstanceOf(Error);
  });

  it('keeps the active queue healthy when only resolved, stats, or session reads fail', async () => {
    const finding = { finding_id: 'finding-active', status: 'open' };
    fetchActiveFindings.mockResolvedValue({ findings: [finding], total: 1 });
    fetchResolvedFindings.mockRejectedValue(new Error('resolved failed'));
    fetchFindingStats.mockRejectedValue(new Error('stats failed'));
    fetchAuthSession.mockRejectedValue(new Error('session failed'));

    const { result } = renderHook(() => useFindings({ pollMs: 0 }));
    await waitFor(() => expect(result.current.phase).toBe('healthy'));
    expect(result.current.findings).toEqual([expect.objectContaining(finding)]);
    expect(result.current.stats).toBeNull();
    expect(result.current.canAdmin).toBe(false);
  });
});
