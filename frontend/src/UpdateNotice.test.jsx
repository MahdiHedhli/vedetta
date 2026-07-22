import React from 'react';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import UpdateNotice, { UPDATE_STATUS_POLL_MS } from './UpdateNotice';

vi.mock('./lib/api', () => ({ authFetch: vi.fn() }));
import { authFetch } from './lib/api';

function mockStatus(status) {
  authFetch.mockResolvedValue({ ok: true, json: async () => status });
}

describe('UpdateNotice', () => {
  beforeEach(() => {
    localStorage.clear();
    authFetch.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows a software-update banner with a release link', async () => {
    mockStatus({
      enabled: true,
      software: {
        current: 'v1.2.0',
        latest: 'v1.3.0',
        update_available: true,
        url: 'https://github.com/x/y/releases/tag/v1.3.0',
      },
      device_db: { update_available: false },
    });
    render(<UpdateNotice />);
    expect(await screen.findByText(/Vedetta v1\.3\.0 is available/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Release notes' })).toHaveAttribute(
      'href',
      'https://github.com/x/y/releases/tag/v1.3.0',
    );
  });

  it('shows a device-DB banner', async () => {
    mockStatus({
      enabled: true,
      software: { update_available: false },
      device_db: { latest: 'db-2026.07', update_available: true },
    });
    render(<UpdateNotice />);
    expect(await screen.findByText(/newer device database \(db-2026\.07\)/)).toBeInTheDocument();
  });

  it('gives simultaneous dismiss controls distinct accessible names', async () => {
    mockStatus({
      enabled: true,
      software: { latest: 'v1.3.0', update_available: true },
      device_db: { latest: 'db-2026.07', update_available: true },
    });
    render(<UpdateNotice />);
    expect(
      await screen.findByRole('button', { name: 'Dismiss Vedetta software update notice' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Dismiss device database update notice' }),
    ).toBeInTheDocument();
  });

  it('renders nothing when disabled', async () => {
    mockStatus({ enabled: false });
    const { container } = render(<UpdateNotice />);
    await waitFor(() => expect(authFetch).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when no update is available', async () => {
    mockStatus({
      enabled: true,
      software: { update_available: false },
      device_db: { update_available: false },
    });
    const { container } = render(<UpdateNotice />);
    await waitFor(() => expect(authFetch).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('dismisses a notice and remembers it per tag', async () => {
    mockStatus({
      enabled: true,
      software: { latest: 'v1.3.0', update_available: true },
      device_db: { update_available: false },
    });
    render(<UpdateNotice />);
    expect(await screen.findByText(/Vedetta v1\.3\.0 is available/)).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: 'Dismiss Vedetta software update notice' }),
    );
    await waitFor(() =>
      expect(screen.queryByText(/Vedetta v1\.3\.0 is available/)).not.toBeInTheDocument(),
    );
    expect(localStorage.getItem('vedetta_update_dismissed:software:v1.3.0')).toBe('1');
  });

  it('refreshes status while the dashboard remains open', async () => {
    vi.useFakeTimers();
    authFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          enabled: true,
          software: { update_available: false },
          device_db: { update_available: false },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          enabled: true,
          software: { latest: 'v1.4.0', update_available: true },
          device_db: { update_available: false },
        }),
      });

    render(<UpdateNotice />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(authFetch).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(UPDATE_STATUS_POLL_MS);
    });
    expect(authFetch).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/Vedetta v1\.4\.0 is available/)).toBeInTheDocument();
  });

  it('keeps the last visible notice when a later poll fails', async () => {
    vi.useFakeTimers();
    authFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          enabled: true,
          software: { latest: 'v1.4.0', update_available: true },
          device_db: { update_available: false },
        }),
      })
      .mockResolvedValueOnce({ ok: false });

    render(<UpdateNotice />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText(/Vedetta v1\.4\.0 is available/)).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(UPDATE_STATUS_POLL_MS);
    });
    expect(authFetch).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/Vedetta v1\.4\.0 is available/)).toBeInTheDocument();
  });

  it('refetches immediately when the browser credential changes', async () => {
    authFetch
      .mockResolvedValueOnce({ ok: false })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          enabled: true,
          software: { latest: 'v1.4.0', update_available: true },
          device_db: { update_available: false },
        }),
      });

    const { rerender } = render(<UpdateNotice authRefreshKey="" />);
    await waitFor(() => expect(authFetch).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/Vedetta v1\.4\.0 is available/)).not.toBeInTheDocument();

    rerender(<UpdateNotice authRefreshKey="replacement-admin-token" />);
    expect(await screen.findByText(/Vedetta v1\.4\.0 is available/)).toBeInTheDocument();
    expect(authFetch).toHaveBeenCalledTimes(2);
  });
});
