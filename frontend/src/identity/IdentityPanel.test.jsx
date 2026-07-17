import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { confirmDeviceIdentity, listActiveDeviceMerges, mergeDevices, splitDeviceMerge } from './api';
import { IdentityPanel } from './IdentityPanel';

vi.mock('./api', () => ({
  confirmDeviceIdentity: vi.fn(),
  listActiveDeviceMerges: vi.fn(),
  mergeDevices: vi.fn(),
  splitDeviceMerge: vi.fn(),
}));

const source = {
  device_id: 'device-source',
  display_name: 'Hallway camera',
  identity_confidence: 0.42,
  segment: 'iot',
  sensor_id: 'sensor-1',
  signals: [{ field: 'mac', value: '00:00:5E:00:53:01' }],
};
const target = {
  device_id: 'device-target',
  canonical_device_id: 'device-canonical',
  display_name: 'Camera (confirmed)',
  identity_confidence: 0.99,
};

describe('Needs Identification workflow', () => {
  beforeEach(() => {
    listActiveDeviceMerges.mockReset().mockResolvedValue({ actions: [] });
    confirmDeviceIdentity.mockReset().mockResolvedValue({ action_id: 'confirm-audit', action_type: 'confirm' });
    mergeDevices.mockReset().mockResolvedValue({ action_id: 'merge-audit', action_type: 'merge', source_device_id: 'device-source', target_device_id: 'device-canonical' });
    splitDeviceMerge.mockReset().mockResolvedValue({ action_id: 'split-audit', action_type: 'split' });
  });

  it('confirms selected evidence as an audited operator action', async () => {
    const user = userEvent.setup();
    const changed = vi.fn();
    render(<IdentityPanel devices={[source, target]} canAdmin={true} onChanged={changed} />);

    await user.type(screen.getByLabelText(/Confirmation reason/), 'Matched the asset inventory label');
    await user.click(screen.getByRole('button', { name: 'Confirm identity' }));

    await waitFor(() => expect(confirmDeviceIdentity).toHaveBeenCalledWith('device-source', expect.objectContaining({
      evidence: expect.objectContaining({ type: 'mac', value: '00:00:5E:00:53:01' }),
      reason: 'Matched the asset inventory label',
    })));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ action_id: 'confirm-audit' }));
    expect(screen.getByRole('status')).toHaveTextContent('audit confirm-audit');
    // The server remains authoritative. If the next device payload still says
    // this identity is low-confidence, the conflict must remain visible.
    expect(screen.getAllByText('Hallway camera').length).toBeGreaterThan(0);
  });

  it('confirms without a reason because the reason field is optional', async () => {
    const user = userEvent.setup();
    render(<IdentityPanel devices={[source, target]} canAdmin={true} onChanged={vi.fn()} />);

    // No reason typed. The operator can still confirm; the server backfills the audit reason.
    await user.click(screen.getByRole('button', { name: 'Confirm identity' }));

    await waitFor(() => expect(confirmDeviceIdentity).toHaveBeenCalledWith('device-source', expect.objectContaining({
      evidence: expect.objectContaining({ type: 'mac', value: '00:00:5E:00:53:01' }),
      reason: '',
    })));
  });

  it('starts collapsed when the queue is large enough to dominate the page', async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 9 }, (_, index) => ({
      device_id: `device-${index}`,
      display_name: `Camera ${index}`,
      identity_confidence: 0.42,
      signals: [{ field: 'mac', value: `00:00:5E:00:53:${index.toString(16).padStart(2, '0')}` }],
    }));
    render(<IdentityPanel devices={many} canAdmin={true} onChanged={vi.fn()} />);

    // The header stays, but the body (merge tooling) is hidden until the operator expands it.
    expect(screen.getByRole('heading', { name: 'Needs Identification' })).toBeInTheDocument();
    const toggle = screen.getByRole('button', { name: 'Expand' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText('Merge duplicate device records')).not.toBeInTheDocument();

    await user.click(toggle);
    expect(screen.getByText('Merge duplicate device records')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Collapse' })).toHaveAttribute('aria-expanded', 'true');
  });

  it('stays expanded for a small queue', () => {
    render(<IdentityPanel devices={[source, target]} canAdmin={true} onChanged={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Collapse' })).toBeInTheDocument();
    expect(screen.getByText('Merge duplicate device records')).toBeInTheDocument();
  });

  it('navigates to the canonical device after merge and can auditably undo it', async () => {
    const user = userEvent.setup();
    const navigate = vi.fn();
    render(<IdentityPanel devices={[source, target]} canAdmin={true} onNavigateDevice={navigate} />);

    await user.type(screen.getByLabelText('Merge reason'), 'Duplicate observations of one camera');
    await user.click(screen.getByRole('button', { name: 'Merge as same asset' }));

    await waitFor(() => expect(mergeDevices).toHaveBeenCalledWith('device-source', 'device-canonical', 'Duplicate observations of one camera'));
    expect(navigate).toHaveBeenCalledWith('device-canonical');

    await user.type(await screen.findByLabelText('Undo reason'), 'Different serial numbers');
    await user.click(screen.getByRole('button', { name: 'Undo merge' }));
    await waitFor(() => expect(splitDeviceMerge).toHaveBeenCalledWith('merge-audit', 'Different serial numbers'));
  });

  it('shows identification needs but hides mutations for explicit read-only access', () => {
    render(<IdentityPanel devices={[source, target]} canAdmin={false} />);
    expect(screen.getByText('Hallway camera')).toBeInTheDocument();
    expect(screen.getAllByText(/Admin access is required/).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: 'Confirm identity' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Merge as same asset' })).not.toBeInTheDocument();
  });

  it('derives a low-confidence device from the latest event identity DTO', () => {
    const deviceWithoutSummary = { ...source };
    delete deviceWithoutSummary.identity_confidence;
    render(<IdentityPanel
      devices={[deviceWithoutSummary, target]}
      events={[{ device_id: 'device-source', identity_confidence: 0.31, identity_reason: 'temporal_ip_binding', timestamp: '2026-07-12T12:00:00Z' }]}
      canAdmin={false}
    />);
    expect(screen.getByText('31% identity confidence')).toBeInTheDocument();
  });

  it('allows an admin to merge a high-confidence device pair', async () => {
    const user = userEvent.setup();
    const highA = { ...source, device_id: 'high-a', display_name: 'Camera record A', identity_confidence: 0.99 };
    const highB = { ...target, device_id: 'high-b', canonical_device_id: 'high-b', display_name: 'Camera record B' };
    mergeDevices.mockResolvedValue({ action_id: 'high-merge', target_device_id: 'high-b' });
    render(<IdentityPanel devices={[highA, highB]} canAdmin={true} />);

    expect(screen.getByText(/No device currently reports/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('Merge reason'), 'Operator verified duplicate serial number');
    await user.click(screen.getByRole('button', { name: 'Merge as same asset' }));
    await waitFor(() => expect(mergeDevices).toHaveBeenCalledWith('high-a', 'high-b', 'Operator verified duplicate serial number'));
  });

  it('loads a prior active merge and can undo it after reload', async () => {
    const user = userEvent.setup();
    const activeMerge = {
      action_id: 'persisted-merge',
      source_device_id: 'old-source',
      target_device_id: 'old-target',
      canonical_target_device_id: 'current-target',
      source_display_name: 'Old camera record',
      target_display_name: 'Current camera record',
      reason: 'duplicate',
    };
    listActiveDeviceMerges
      .mockResolvedValueOnce({ actions: [activeMerge] })
      .mockResolvedValue({ actions: [] });
    render(<IdentityPanel devices={[source, target]} canAdmin={true} />);

    expect(await screen.findByText(/Old camera record/)).toBeInTheDocument();
    expect(screen.getByText(/Current camera record/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('Undo reason'), 'Post-reload audit found distinct hardware');
    await user.click(screen.getByRole('button', { name: 'Undo merge' }));
    await waitFor(() => expect(splitDeviceMerge).toHaveBeenCalledWith('persisted-merge', 'Post-reload audit found distinct hardware'));
  });

  it('lets read scope inspect merge audit without exposing undo controls', async () => {
    listActiveDeviceMerges.mockResolvedValue({ actions: [{
      action_id: 'read-visible-merge',
      source_device_id: 'source-read',
      target_device_id: 'target-read',
      canonical_target_device_id: 'canonical-read',
      source_display_name: 'Duplicate sensor',
      target_display_name: 'Canonical sensor',
      reason: 'same hardware',
    }] });
    render(<IdentityPanel devices={[source, target]} canAdmin={false} />);
    expect(await screen.findByText(/Duplicate sensor/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View target' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Undo merge' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Undo reason')).not.toBeInTheDocument();
  });
});
