import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./lib/api', () => ({
  CORE_BASE: '',
  authFetch: vi.fn(),
  authFetchJSON: vi.fn(),
  clearAdminToken: vi.fn(),
  getAdminToken: vi.fn(() => ''),
  hasAdminToken: vi.fn(() => false),
  setAdminToken: vi.fn(),
}));

import { authFetch } from './lib/api';
import { SensorsView } from './App';

const removed = {
  sensor_id: 'sensor/removed',
  hostname: 'old-pi',
  os: 'linux',
  arch: 'arm64',
  version: '0.1.0',
  last_seen: '2026-07-13T12:00:00Z',
  removed_at: '2026-07-14T12:00:00Z',
  removal_reason: 'removed by operator',
};

const active = {
  sensor_id: 'sensor-active',
  hostname: 'active-pi',
  os: 'linux',
  arch: 'arm64',
  version: '0.1.0',
  cidr: '192.0.2.0/24',
  first_seen: '2026-07-12T12:00:00Z',
  last_seen: '2026-07-14T12:00:00Z',
  status: 'online',
  is_primary: false,
};

describe('SensorsView sensor lifecycle', () => {
  beforeEach(() => authFetch.mockReset());

  it('shows retained removed identities even when there are no active sensors', () => {
    render(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);

    expect(screen.getByText('No sensors connected')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Removed sensors' })).toBeInTheDocument();
    expect(screen.getByText('old-pi')).toBeInTheDocument();
    expect(screen.getByText('sensor/removed')).toBeInTheDocument();
  });

  it('requests an exact bound reset code and displays it only after validating the response', async () => {
    authFetch.mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({
        type: 'reset',
        sensor_id: removed.sensor_id,
        enrollment_code: 'ABCD-EFGH-IJKL-MNOP',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      }),
    });
    const user = userEvent.setup();
    render(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: 'Generate reset code' }));

    expect(authFetch).toHaveBeenCalledWith('/api/v1/enrollment-codes', {
      method: 'POST',
      body: { sensor_id: removed.sensor_id },
    });
    expect(await screen.findByText('ABCD-EFGH-IJKL-MNOP')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
    expect(screen.getByText(/Minting this code does not reactivate/)).toBeInTheDocument();
  });

  it('forgets a one-time code when the sensor leaves the removed partition', async () => {
    authFetch.mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({
        type: 'reset',
        sensor_id: removed.sensor_id,
        enrollment_code: 'ONE-TIME-CODE',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      }),
    });
    const user = userEvent.setup();
    const view = render(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: 'Generate reset code' }));
    expect(await screen.findByText('ONE-TIME-CODE')).toBeInTheDocument();

    view.rerender(<SensorsView sensors={[]} removedSensors={[]} onSetup={vi.fn()} />);
    await waitFor(() => expect(screen.queryByText('ONE-TIME-CODE')).not.toBeInTheDocument());
    view.rerender(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);
    expect(screen.queryByText('ONE-TIME-CODE')).not.toBeInTheDocument();
  });

  it('removes an expired reset code from the page', async () => {
    const now = Date.parse('2026-07-14T12:00:00Z');
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);
    try {
      authFetch.mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          type: 'reset',
          sensor_id: removed.sensor_id,
          enrollment_code: 'SHORT-LIVED-CODE',
          expires_at: new Date(now + 60_000).toISOString(),
        }),
      });
      const user = userEvent.setup();
      const view = render(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);

      await user.click(screen.getByRole('button', { name: 'Generate reset code' }));
      expect(await screen.findByText('SHORT-LIVED-CODE')).toBeInTheDocument();

      // Re-evaluate the lifecycle effect after the fixed clock passes expiry.
      // This avoids a wall-clock race on loaded CI runners.
      clock.mockReturnValue(now + 61_000);
      view.rerender(<SensorsView sensors={[]} removedSensors={[{ ...removed }]} onSetup={vi.fn()} />);
      await waitFor(() => expect(screen.queryByText('SHORT-LIVED-CODE')).not.toBeInTheDocument());
    } finally {
      clock.mockRestore();
    }
  });

  it('rejects a generic or mismatched code response instead of displaying the secret', async () => {
    authFetch.mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({
        type: 'new_sensor',
        sensor_id: removed.sensor_id,
        enrollment_code: 'SHOULD-NOT-SHOW',
      }),
    });
    const user = userEvent.setup();
    render(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: 'Generate reset code' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Core returned an invalid reset code response.');
    expect(screen.queryByText('SHOULD-NOT-SHOW')).not.toBeInTheDocument();
  });

  it('awaits the post-action refresh and surfaces a refresh failure', async () => {
    authFetch.mockResolvedValue({ ok: true, json: vi.fn().mockResolvedValue({}) });
    let rejectRefresh;
    const refresh = vi.fn(() => new Promise((_, reject) => { rejectRefresh = reject; }));
    const user = userEvent.setup();
    render(<SensorsView sensors={[active]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

    await user.click(screen.getByRole('button', { name: 'Make Primary' }));
    expect(screen.getByRole('button', { name: 'Updating…' })).toBeDisabled();
    rejectRefresh(new Error('Sensor list refresh failed'));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Sensor list refresh failed'));
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Make Primary' })).not.toBeDisabled();
  });

  it('does not remove a sensor when the operator cancels confirmation', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    try {
      const refresh = vi.fn();
      const user = userEvent.setup();
      render(<SensorsView sensors={[active]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

      await user.click(screen.getByRole('button', { name: 'Remove' }));

      expect(confirm).toHaveBeenCalledTimes(1);
      expect(authFetch).not.toHaveBeenCalled();
      expect(refresh).not.toHaveBeenCalled();
    } finally {
      confirm.mockRestore();
    }
  });

  it('removes a confirmed sensor and surfaces a post-delete refresh failure', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    try {
      authFetch.mockResolvedValue({ ok: true, json: vi.fn().mockResolvedValue({}) });
      const refresh = vi.fn().mockRejectedValue(new Error('Sensor list refresh failed after removal'));
      const user = userEvent.setup();
      render(<SensorsView sensors={[active]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

      await user.click(screen.getByRole('button', { name: 'Remove' }));

      expect(authFetch).toHaveBeenCalledWith('/api/v1/sensor/sensor-active', { method: 'DELETE' });
      expect(refresh).toHaveBeenCalledTimes(1);
      expect(await screen.findByRole('alert')).toHaveTextContent('Sensor list refresh failed after removal');
      expect(screen.getByRole('button', { name: 'Remove' })).not.toBeDisabled();
    } finally {
      confirm.mockRestore();
    }
  });
});
