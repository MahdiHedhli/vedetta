import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import {
  DetectionStatePanel,
  FindingCard,
  FindingsDashboardSummary,
  FindingsView,
  FindingsWorkspace,
} from './FindingsView';

const healthyHealth = {
  state: 'healthy',
  sources: [{ name: 'sensor DNS', state: 'healthy', event_count: 42, last_success: '2026-07-12T12:00:00Z' }],
  feeds: [{ name: 'Feodo Tracker', state: 'healthy', item_count: 800, last_success: '2026-07-12T12:00:00Z' }],
};

const cameraFinding = {
  finding_id: 'finding-1',
  finding_key: 'stable-key',
  device_id: 'device-stable-123',
  detector: 'threat_intel',
  category: 'Known command and control',
  primary_observable_type: 'destination_ip',
  primary_observable: '192.0.2.44',
  first_seen: '2026-07-12T10:00:00Z',
  last_seen: '2026-07-12T10:12:00Z',
  occurrence_count: 17,
  current_priority: 'high',
  outcome: 'allowed',
  status: 'open',
  reason: 'This destination is listed by Feodo Tracker as command-and-control infrastructure.',
  recommended_action: 'Isolate the camera and check for firmware updates.',
  last_event_id: 'event-17',
};

const baseState = {
  phase: 'healthy',
  findings: [cameraFinding],
  stats: { open_by_priority: { critical: 0, high: 1 }, affected_devices: 1, recently_resolved: 0 },
  health: healthyHealth,
  refreshing: false,
  refresh: vi.fn(),
  loadDetail: vi.fn().mockResolvedValue({ finding: cameraFinding, evidence: [] }),
  updateStatus: vi.fn().mockResolvedValue(cameraFinding),
};

describe('findings health states', () => {
  it('distinguishes a healthy empty result from retrieval failure', () => {
    const { rerender } = render(<DetectionStatePanel phase="healthy-empty" health={healthyHealth} />);

    expect(screen.getByText('No actionable findings')).toBeInTheDocument();
    expect(screen.getByText(/Collection and threat feeds are reporting healthy/)).toBeInTheDocument();

    rerender(<DetectionStatePanel phase="error" error={new Error('request failed')} />);

    expect(screen.getByRole('alert')).toHaveTextContent('Findings unavailable');
    expect(screen.getByRole('alert')).toHaveTextContent('request failed');
    expect(screen.queryByText('No actionable findings')).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('error');
    expect(screen.getByRole('alert')).not.toHaveTextContent('healthy');
    expect(screen.queryByText(/network is secure/i)).not.toBeInTheDocument();
  });

  it('presents authentication failure separately', () => {
    render(<DetectionStatePanel phase="unauthorized" />);
    expect(screen.getByRole('alert')).toHaveTextContent('Authentication required');
    expect(screen.getByRole('alert')).not.toHaveTextContent('No actionable findings');
  });

  it('distinguishes coverage-health failure from an active findings fetch failure', () => {
    render(<DetectionStatePanel phase="health-error" health={healthyHealth} error={new Error('health endpoint timed out')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Detection health is unavailable or degraded');
    expect(screen.getByRole('alert')).toHaveTextContent('Active findings loaded');
    expect(screen.getByRole('alert')).not.toHaveTextContent('Findings unavailable');
    expect(screen.getByRole('alert')).toHaveTextContent('error');
  });

  it('does not present stale finding metrics as confident zeros', () => {
    render(<FindingsDashboardSummary state={{ phase: 'stale', stats: { open_by_priority: {}, affected_devices: 0, recently_resolved: 0 } }} />);
    expect(screen.getAllByText('—')).toHaveLength(3);
    expect(screen.queryByText(/^0$/)).not.toBeInTheDocument();
    expect(screen.getByText('Review stale sources')).toBeInTheDocument();
  });
});

describe('finding presentation', () => {
  it('shows allowed and blocked outcomes without changing priority', () => {
    const blocked = { ...cameraFinding, finding_id: 'finding-2', outcome: 'blocked', current_priority: 'critical' };
    render(
      <>
        <FindingCard finding={cameraFinding} />
        <FindingCard finding={blocked} />
      </>
    );

    expect(screen.getByText('Allowed')).toBeInTheDocument();
    expect(screen.getByText('Blocked')).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(screen.getByText('critical')).toBeInTheDocument();
  });

  it('distinguishes observed activity from allowed traffic', () => {
    render(<FindingCard finding={{ ...cameraFinding, outcome: 'observed', blocked: false, allowed_count: 0, blocked_count: 0, observed_count: 3 }} />);

    expect(screen.getByText('Observed')).toBeInTheDocument();
    expect(screen.queryByText('Allowed')).not.toBeInTheDocument();
    expect(screen.getByText('0 allowed · 0 blocked · 3 observed')).toBeInTheDocument();
  });

  it('opens typed evidence and supporting raw events as a drill-down', async () => {
    const user = userEvent.setup();
    const loadDetail = vi.fn().mockResolvedValue({
      finding: cameraFinding,
      evidence: [{
        evidence_id: 'evidence-1',
        detector_name: 'ioc_match',
        observable_type: 'destination_ip',
        observable_value: '192.0.2.44',
        threat_intel_source: 'Feodo Tracker',
        rationale: 'Exact destination-IP match.',
        source_confidence: 0.95,
        score_contribution: 0.72,
        feed_freshness: '2026-07-12T09:00:00Z',
        feed_stale: true,
        event_id: 'event-17',
        category: 'known_c2',
        outcome: 'allowed',
        device_context: {
          device_type: 'camera',
          model: 'Cam 4',
          segment: 'iot',
          risk_category: 'end_of_life',
          risk_model: 'high',
          eol_risk: true,
          identity_confidence: 0.94,
          identity_status: 'resolved',
        },
      }],
      supporting_events: [{
        event_id: 'event-17',
        event_type: 'dns_query',
        timestamp: '2026-07-12T10:12:00Z',
        resolved_ip: '198.51.100.7',
        origin: 'sensor_dns',
        sensor_id: 'sensor-lan',
        device_id: 'device-stable-123',
        identity_confidence: 0.94,
        identity_reason: 'temporal_address_binding',
        disposition: 'active',
      }],
      evidence_total: 140,
      supporting_event_total: 217,
    });

    render(<FindingCard finding={cameraFinding} onLoadDetail={loadDetail} />);
    await user.click(screen.getByRole('button', { name: 'View evidence' }));

    await waitFor(() => expect(loadDetail).toHaveBeenCalledWith('finding-1'));
    expect(await screen.findByText('ioc_match')).toBeInTheDocument();
    expect(screen.getByText('Exact destination-IP match.')).toBeInTheDocument();
    expect(screen.getByText('feed stale')).toBeInTheDocument();
    expect(screen.getByText('Type: camera')).toBeInTheDocument();
    expect(screen.getByText('Model: Cam 4')).toBeInTheDocument();
    expect(screen.getByText('Segment: iot')).toBeInTheDocument();
    expect(screen.getByText('Lifecycle: End-of-life / elevated risk')).toBeInTheDocument();
    expect(screen.getByText(/198\.51\.100\.7/)).toBeInTheDocument();
    expect(within(screen.getByRole('list', { name: 'Supporting raw events' })).getByText(/event-17/)).toBeInTheDocument();
    expect(screen.getByText(/origin sensor_dns/)).toHaveTextContent('sensor sensor-lan');
    expect(screen.getByText(/origin sensor_dns/)).toHaveTextContent('identity 94% (temporal_address_binding)');
    expect(screen.getByText('Showing the newest 1 of 140 evidence records.')).toBeInTheDocument();
    expect(screen.getByText('Showing the newest 1 of 217 supporting raw events.')).toBeInTheDocument();
  });

  it('pages evidence and supporting events until record 101 is reachable', async () => {
    const user = userEvent.setup();
    const evidence = Array.from({ length: 100 }, (_, index) => ({
      evidence_id: `evidence-${index + 1}`, detector_name: `detector ${index + 1}`,
    }));
    const events = Array.from({ length: 100 }, (_, index) => ({
      event_id: `event-${index + 1}`, timestamp: '2026-07-12T10:12:00Z', event_type: 'dns_query',
    }));
    const loadDetail = vi.fn()
      .mockResolvedValueOnce({ finding: cameraFinding, evidence, supporting_events: events, evidence_total: 101, supporting_event_total: 101 })
      .mockResolvedValueOnce({ finding: cameraFinding, evidence: [{ evidence_id: 'evidence-101', detector_name: 'detector 101' }], supporting_events: events, evidence_total: 101, supporting_event_total: 101 })
      .mockResolvedValueOnce({ finding: cameraFinding, evidence, supporting_events: [{ event_id: 'event-101', timestamp: '2026-07-12T10:13:00Z', event_type: 'dns_query' }], evidence_total: 101, supporting_event_total: 101 });

    render(<FindingCard finding={cameraFinding} onLoadDetail={loadDetail} />);
    await user.click(screen.getByRole('button', { name: 'View evidence' }));
    await user.click(await screen.findByRole('button', { name: 'Load more evidence' }));
    expect(await screen.findByText('detector 101')).toBeInTheDocument();
    expect(loadDetail).toHaveBeenNthCalledWith(2, 'finding-1', { evidenceOffset: 100, eventOffset: 0 });

    await user.click(screen.getByRole('button', { name: 'Load more events' }));
    expect(await within(screen.getByRole('list', { name: 'Supporting raw events' })).findByText(/event-101/)).toBeInTheDocument();
    expect(loadDetail).toHaveBeenNthCalledWith(3, 'finding-1', { evidenceOffset: 0, eventOffset: 100 });
  });

  it('uses stable device_id navigation even when the current IP changes', async () => {
    const user = userEvent.setup();
    const navigate = vi.fn();
    const firstDevice = { device_id: 'device-stable-123', hostname: 'living-room-camera', ip_address: '192.0.2.10' };
    const { rerender } = render(<FindingCard finding={cameraFinding} device={firstDevice} onNavigateDevice={navigate} />);

    await user.click(screen.getByRole('button', { name: 'View device' }));
    expect(navigate).toHaveBeenLastCalledWith('device-stable-123');

    rerender(<FindingCard finding={cameraFinding} device={{ ...firstDevice, ip_address: '192.0.2.99' }} onNavigateDevice={navigate} />);
    await user.click(screen.getByRole('button', { name: 'View device' }));
    expect(navigate).toHaveBeenLastCalledWith('device-stable-123');
    expect(screen.getByText(/living-room-camera/)).toBeInTheDocument();
  });

  it('uses the canonical merged device for navigation and backend display_name', async () => {
    const user = userEvent.setup();
    const navigate = vi.fn();
    const mergedFinding = { ...cameraFinding, device_id: 'device-source', canonical_device_id: 'device-target' };
    render(<FindingCard finding={mergedFinding} device={{ device_id: 'device-target', display_name: 'Canonical camera' }} onNavigateDevice={navigate} />);
    expect(screen.getByText(/Canonical camera/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'View device' }));
    expect(navigate).toHaveBeenCalledWith('device-target');
  });

  it('labels a low-confidence associated device as tentative without hiding its stable link', async () => {
    const user = userEvent.setup();
    const navigate = vi.fn();
    const tentativeFinding = {
      ...cameraFinding,
      identity_confidence: 0.42,
      identity_status: 'low_confidence',
      needs_identification: true,
    };
    render(
      <FindingCard
        finding={tentativeFinding}
        device={{ device_id: 'device-stable-123', display_name: 'Possible living-room camera' }}
        onNavigateDevice={navigate}
      />
    );

    expect(screen.getByText('needs identification')).toBeInTheDocument();
    expect(screen.getByText(/tentative, 42% identity confidence/)).toBeInTheDocument();
    expect(screen.getByText(/Possible living-room camera/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'View device' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'View tentative device' }));
    expect(navigate).toHaveBeenCalledWith('device-stable-123');
  });

  it('does not let a mutable low-confidence device override high event-time attribution', () => {
    render(
      <FindingCard
        finding={{ ...cameraFinding, identity_confidence: 0.94, identity_reason: 'stable_identity_evidence', needs_identification: false }}
        device={{
          device_id: 'device-stable-123',
          display_name: 'Living-room camera',
          identity_confidence: 0.42,
          needs_identification: true,
        }}
      />
    );

    expect(screen.queryByText('needs identification')).not.toBeInTheDocument();
    expect(screen.queryByText(/tentative/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View device' })).toBeInTheDocument();
  });

  it('honors a device-level needs-identification projection when the finding has no confidence', () => {
    render(
      <FindingCard
        finding={cameraFinding}
        device={{
          device_id: 'device-stable-123',
          display_name: 'Possible camera',
          identity_confidence: 0.65,
          needs_identification: true,
        }}
      />
    );

    expect(screen.getByText(/tentative, 65% identity confidence/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View tentative device' })).toBeInTheDocument();
  });

  it('hides lifecycle mutations when the caller explicitly knows access is read-only', () => {
    render(<FindingCard finding={cameraFinding} canAdmin={false} onSuppress={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Update status' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Suppress similar' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View evidence' })).toBeInTheDocument();
  });

  it('labels community evidence as advisory corroboration and omits priority contribution', async () => {
    const user = userEvent.setup();
    const loadDetail = vi.fn().mockResolvedValue({
      finding: cameraFinding,
      evidence: [{
        evidence_id: 'community-evidence',
        detector_name: 'community_match',
        threat_intel_source: 'vedetta-community',
        observable_type: 'domain',
        observable_value: 'badzone.example',
        score_contribution: 0.99,
      }],
    });
    render(<FindingCard finding={cameraFinding} onLoadDetail={loadDetail} />);
    await user.click(screen.getByRole('button', { name: 'View evidence' }));

    expect(await screen.findByText('advisory corroboration')).toBeInTheDocument();
    expect(screen.getByText(/does not drive finding priority/)).toBeInTheDocument();
    expect(screen.queryByText('score +0.99')).not.toBeInTheDocument();
  });

  it('refreshes expanded detail when polling updates the finding headline', async () => {
    const user = userEvent.setup();
    const initialDetail = { finding: cameraFinding, evidence: [{ detector_name: 'initial evidence' }] };
    const refreshedFinding = { ...cameraFinding, occurrence_count: 18, last_event_id: 'event-18', updated_at: '2026-07-12T10:13:00Z' };
    const loadDetail = vi.fn()
      .mockResolvedValueOnce(initialDetail)
      .mockResolvedValueOnce({ finding: refreshedFinding, evidence: [{ detector_name: 'refreshed evidence' }] });
    const { rerender } = render(<FindingCard finding={cameraFinding} onLoadDetail={loadDetail} />);

    await user.click(screen.getByRole('button', { name: 'View evidence' }));
    expect(await screen.findByText('initial evidence')).toBeInTheDocument();
    rerender(<FindingCard finding={refreshedFinding} onLoadDetail={loadDetail} />);

    await waitFor(() => expect(loadDetail).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('refreshed evidence')).toBeInTheDocument();
  });
});

describe('finding lifecycle', () => {
  it('requires a resolution reason and sends the finding-level lifecycle update', async () => {
    const user = userEvent.setup();
    const updateStatus = vi.fn().mockResolvedValue({ ...cameraFinding, status: 'resolved' });
    render(<FindingCard finding={cameraFinding} onUpdateStatus={updateStatus} />);

    await user.click(screen.getByRole('button', { name: 'Update status' }));
    await user.selectOptions(screen.getByLabelText('Status'), 'resolved');
    await user.click(screen.getByRole('button', { name: 'Save status' }));
    expect(screen.getByRole('alert')).toHaveTextContent('A reason is required');
    expect(updateStatus).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText(/Reason/), 'Firmware updated and device isolated');
    await user.click(screen.getByRole('button', { name: 'Save status' }));

    await waitFor(() => expect(updateStatus).toHaveBeenCalledWith(
      'finding-1',
      'resolved',
      'Firmware updated and device isolated'
    ));
    await user.click(screen.getByRole('button', { name: 'Update status' }));
    expect(screen.getByLabelText('Status')).toHaveValue('resolved');
  });

  it('requires a reason before creating a finding-level suppression rule', async () => {
    const user = userEvent.setup();
    const suppress = vi.fn().mockResolvedValue({ rule: { rule_id: 'rule-1' } });
    render(<FindingCard finding={cameraFinding} canAdmin onSuppress={suppress} />);

    await user.click(screen.getByRole('button', { name: 'Suppress similar' }));
    await user.click(screen.getByRole('button', { name: 'Create suppression' }));
    expect(screen.getByRole('alert')).toHaveTextContent('A reason is required');
    expect(suppress).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText('Suppression reason (required)'), 'Expected camera update service');
    await user.click(screen.getByRole('button', { name: 'Create suppression' }));
    await waitFor(() => expect(suppress).toHaveBeenCalledWith('finding-1', 'Expected camera update service'));
  });

  it('removes the exact typed rule from a suppressed finding', async () => {
    const user = userEvent.setup();
    const unsuppress = vi.fn().mockResolvedValue({});
    const suppressed = { ...cameraFinding, disposition: 'suppressed', suppression_rule_id: 'rule-17' };
    render(<FindingCard finding={suppressed} canAdmin onUnsuppress={unsuppress} />);

    await user.click(screen.getByRole('button', { name: 'Unsuppress' }));
    await waitFor(() => expect(unsuppress).toHaveBeenCalledWith('finding-1', 'rule-17'));
  });
});

describe('findings workspace', () => {
  it('keeps raw events as an explicit secondary view', async () => {
    const user = userEvent.setup();
    render(<FindingsWorkspace state={baseState} devices={[]} rawEventsView={<div>Legacy raw event table</div>} />);

    expect(screen.getByRole('heading', { name: 'Actionable Findings' })).toBeInTheDocument();
    expect(screen.queryByText('Legacy raw event table')).not.toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Raw events' }));
    expect(screen.getByText('Legacy raw event table')).toBeInTheDocument();
  });

  it('surfaces feed and collection health beside findings', () => {
    render(<FindingsView state={baseState} />);
    const details = screen.getByLabelText('Detection health details');
    expect(within(details).getByText('sensor DNS')).toBeInTheDocument();
    expect(within(details).getByText('Feodo Tracker')).toBeInTheDocument();
  });

  it('excludes suppressed findings from the default queue with explicit access', async () => {
    const user = userEvent.setup();
    const suppressed = {
      ...cameraFinding,
      finding_id: 'suppressed-finding',
      disposition: 'suppressed',
      reason: 'Suppressed camera DNS pattern',
    };
    render(<FindingsView state={{ ...baseState, phase: 'healthy-empty', findings: [suppressed], activeTotal: 1 }} />);

    expect(screen.getByText('No actionable findings')).toBeInTheDocument();
    expect(screen.queryByText('Suppressed camera DNS pattern')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Suppressed' }));
    expect(screen.getByText('Suppressed camera DNS pattern')).toBeInTheDocument();
  });

  it('loads later pages from each queue without changing the other queues', async () => {
    const user = userEvent.setup();
    const loadMore = vi.fn().mockResolvedValue(undefined);
    const active = { ...cameraFinding, finding_id: 'active-one', disposition: 'active' };
    const suppressed = { ...cameraFinding, finding_id: 'suppressed-one', disposition: 'suppressed' };
    const resolved = { ...cameraFinding, finding_id: 'resolved-one', status: 'resolved' };
    render(<FindingsView state={{
      ...baseState,
      findings: [active, suppressed, resolved],
      activeFindings: [active],
      suppressedFindings: [suppressed],
      resolvedFindings: [resolved],
      activeTotal: 101,
      suppressedTotal: 101,
      resolvedTotal: 101,
      loadMore,
      queueLoading: {},
      queueErrors: {},
    }} />);

    await user.click(screen.getByRole('button', { name: 'Load more actionable findings' }));
    expect(loadMore).toHaveBeenLastCalledWith('active');
    expect(screen.getByText('Allowed')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Suppressed' }));
    await user.click(screen.getByRole('button', { name: 'Load more suppressed findings' }));
    expect(loadMore).toHaveBeenLastCalledWith('suppressed');

    await user.click(screen.getByRole('button', { name: 'Resolved' }));
    await user.click(screen.getByRole('button', { name: 'Load more resolved findings' }));
    expect(loadMore).toHaveBeenLastCalledWith('resolved');
  });

  it('makes the All view an explicit union with independent load-more controls', async () => {
    const user = userEvent.setup();
    const loadMore = vi.fn().mockResolvedValue(undefined);
    const active = { ...cameraFinding, finding_id: 'active-one', disposition: 'active' };
    const suppressed = { ...cameraFinding, finding_id: 'suppressed-one', disposition: 'suppressed' };
    const resolved = { ...cameraFinding, finding_id: 'resolved-one', status: 'resolved' };
    render(<FindingsView state={{
      ...baseState,
      findings: [active, suppressed, resolved],
      activeFindings: [active],
      suppressedFindings: [suppressed],
      resolvedFindings: [resolved],
      activeTotal: 2,
      suppressedTotal: 1,
      resolvedTotal: 3,
      loadMore,
      queueLoading: {},
      queueErrors: {},
    }} />);

    await user.click(screen.getByRole('button', { name: 'All' }));
    expect(screen.getByText(/All is the union of the independently loaded/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load more actionable findings' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more suppressed findings' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load more resolved findings' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Load more resolved findings' }));
    expect(loadMore).toHaveBeenCalledWith('resolved');
    await user.click(screen.getByRole('button', { name: 'Load more actionable findings' }));
    expect(loadMore).toHaveBeenCalledWith('active');
  });

  it('does not offer an endless load-more action after the beta prefix cap', () => {
    const loadMore = vi.fn();
    render(<FindingsView state={{
      ...baseState,
      activeFindings: [cameraFinding],
      activeTotal: 5001,
      queueAtCap: { active: true, suppressed: false, resolved: false },
      loadMore,
    }} />);

    expect(screen.getByText(/reached the 5,000-finding beta display limit/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more actionable findings' })).not.toBeInTheDocument();
  });

  it('labels unresolved finding identities as assets or sources, not confirmed devices', () => {
    render(<FindingsView state={baseState} />);
    expect(screen.getByText('Affected assets / sources')).toBeInTheDocument();
    expect(screen.queryByText('Affected devices')).not.toBeInTheDocument();
  });
});
