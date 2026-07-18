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

const minutesAgo = (m) => new Date(Date.now() - m * 60_000).toISOString();

const stalePrimary = {
  sensor_id: 'old', hostname: 'macstudio', os: 'darwin', arch: 'arm64', version: '0.1.0',
  cidr: '192.0.2.0/24', first_seen: '2026-05-27T00:00:00Z', last_seen: minutesAgo(30),
  status: 'offline', is_primary: true,
};
const healthyReplacement = {
  sensor_id: 'new', hostname: 'macstudio', os: 'darwin', arch: 'arm64', version: '0.1.0',
  cidr: '192.0.2.0/24', first_seen: minutesAgo(20), last_seen: minutesAgo(0),
  status: 'online', is_primary: false,
};

describe('SensorsView replace-primary', () => {
  beforeEach(() => authFetch.mockReset());

  it('offers Replace on a healthy sensor when the primary is stale and posts the pinned old primary', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    try {
      authFetch.mockResolvedValue({ ok: true, json: vi.fn().mockResolvedValue({ status: 'replaced', primary: 'new', removed: 'old' }) });
      const refresh = vi.fn().mockResolvedValue();
      const user = userEvent.setup();
      render(<SensorsView sensors={[stalePrimary, healthyReplacement]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

      await user.click(screen.getByRole('button', { name: 'Replace stale primary' }));

      expect(authFetch).toHaveBeenCalledWith('/api/v1/sensor/new/replace-primary', {
        method: 'POST', body: { old_primary_id: 'old', force: false },
      });
      await waitFor(() => expect(refresh).toHaveBeenCalled());
    } finally {
      confirm.mockRestore();
    }
  });

  it('badges a same-hostname candidate as a likely redeploy of the stale primary', () => {
    render(<SensorsView sensors={[stalePrimary, healthyReplacement]} removedSensors={[]} onSetup={vi.fn()} />);
    expect(screen.getByText('likely redeploy of macstudio')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Replace stale primary' })).toBeInTheDocument();
  });

  it('offers no Replace while the primary is online', () => {
    const online = { ...stalePrimary, status: 'online', last_seen: minutesAgo(0) };
    render(<SensorsView sensors={[online, healthyReplacement]} removedSensors={[]} onSetup={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Replace stale primary' })).not.toBeInTheDocument();
    expect(screen.queryByText(/likely redeploy/)).not.toBeInTheDocument();
  });

  it('does not offer Replace until the stale primary passes the grace window', () => {
    const recentlyOffline = { ...stalePrimary, status: 'offline', last_seen: minutesAgo(5) };
    render(<SensorsView sensors={[recentlyOffline, healthyReplacement]} removedSensors={[]} onSetup={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Replace stale primary' })).not.toBeInTheDocument();
  });

  it('explains the dead-end when the only sensor is a stale primary', () => {
    render(<SensorsView sensors={[stalePrimary]} removedSensors={[]} onSetup={vi.fn()} />);
    expect(screen.getByText(/only sensor and it's the primary/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Replace stale primary' })).not.toBeInTheDocument();
  });

  it('aborts cleanly (no error) when the operator declines the stale-replacement override', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(true).mockReturnValueOnce(false);
    try {
      authFetch.mockResolvedValueOnce({ ok: false, status: 409, json: vi.fn().mockResolvedValue({ code: 'replacement_stale', error: 'not online' }) });
      const refresh = vi.fn().mockResolvedValue();
      const offlineReplacement = { ...healthyReplacement, status: 'offline', last_seen: minutesAgo(20) };
      const user = userEvent.setup();
      render(<SensorsView sensors={[stalePrimary, offlineReplacement]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

      await user.click(screen.getByRole('button', { name: 'Replace stale primary' }));

      // Declined the escalation: exactly one POST, no error banner, no refetch.
      expect(authFetch).toHaveBeenCalledTimes(1);
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(refresh).not.toHaveBeenCalled();
    } finally {
      confirm.mockRestore();
    }
  });

  it('re-posts with force after confirming a stale-replacement override', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    try {
      authFetch
        .mockResolvedValueOnce({ ok: false, status: 409, json: vi.fn().mockResolvedValue({ code: 'replacement_stale', error: 'not online' }) })
        .mockResolvedValueOnce({ ok: true, json: vi.fn().mockResolvedValue({ status: 'replaced' }) });
      const refresh = vi.fn().mockResolvedValue();
      const offlineReplacement = { ...healthyReplacement, status: 'offline', last_seen: minutesAgo(20) };
      const user = userEvent.setup();
      render(<SensorsView sensors={[stalePrimary, offlineReplacement]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

      await user.click(screen.getByRole('button', { name: 'Replace stale primary' }));

      await waitFor(() => expect(authFetch).toHaveBeenCalledTimes(2));
      expect(authFetch).toHaveBeenLastCalledWith('/api/v1/sensor/new/replace-primary', {
        method: 'POST', body: { old_primary_id: 'old', force: true },
      });
    } finally {
      confirm.mockRestore();
    }
  });
});

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

  it('keeps the current reset code when regeneration fails', async () => {
    authFetch
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue({
          type: 'reset',
          sensor_id: removed.sensor_id,
          enrollment_code: 'STILL-VALID-CODE',
          expires_at: new Date(Date.now() + 60_000).toISOString(),
        }),
      })
      .mockRejectedValueOnce(new Error('Core is temporarily unavailable'));
    const user = userEvent.setup();
    render(<SensorsView sensors={[]} removedSensors={[removed]} onSetup={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: 'Generate reset code' }));
    expect(await screen.findByText('STILL-VALID-CODE')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Generate reset code' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Core is temporarily unavailable');
    expect(screen.getByText('STILL-VALID-CODE')).toBeInTheDocument();
    expect(authFetch).toHaveBeenCalledTimes(2);
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

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(
      'Sensor is now primary, but refreshing the list failed: Sensor list refresh failed',
    ));
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
      let rejectRefresh;
      const refresh = vi.fn(() => new Promise((_, reject) => { rejectRefresh = reject; }));
      const user = userEvent.setup();
      render(<SensorsView sensors={[active]} removedSensors={[]} onSetup={vi.fn()} onRefreshSensors={refresh} />);

      await user.click(screen.getByRole('button', { name: 'Remove' }));

      expect(authFetch).toHaveBeenCalledWith('/api/v1/sensor/sensor-active', { method: 'DELETE' });
      expect(refresh).toHaveBeenCalledTimes(1);
      expect(screen.getByRole('button', { name: 'Removing…' })).toBeDisabled();
      rejectRefresh(new Error('Sensor list refresh failed after removal'));
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Sensor was removed, but refreshing the list failed: Sensor list refresh failed after removal',
      );
      expect(screen.getByRole('button', { name: 'Remove' })).not.toBeDisabled();
    } finally {
      confirm.mockRestore();
    }
  });
});
