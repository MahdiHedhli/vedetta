import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({
  authFetch: vi.fn(),
  authFetchJSON: vi.fn(),
  token: '',
}));

vi.mock('./lib/api', () => ({
  CORE_BASE: '',
  authFetch: api.authFetch,
  authFetchJSON: api.authFetchJSON,
  clearAdminToken: vi.fn(() => { api.token = ''; }),
  getAdminToken: vi.fn(() => api.token),
  hasAdminToken: vi.fn(() => api.token !== ''),
  setAdminToken: vi.fn((token) => { api.token = token || ''; }),
}));

const findings = vi.hoisted(() => ({
  canAdmin: false,
  phase: 'healthy',
  refresh: vi.fn(),
  session: null,
}));

vi.mock('./findings/useFindings', () => ({
  useFindings: () => ({
    canAdmin: findings.canAdmin,
    findings: [],
    phase: findings.phase,
    refresh: findings.refresh,
    session: findings.session,
  }),
}));

vi.mock('./findings/FindingsView', () => ({
  FindingsDashboardSummary: () => null,
  FindingsWorkspace: () => null,
}));

import App from './App';
import {
  TELEMETRY_NOTICE_STORAGE_KEY,
  TELEMETRY_NOTICE_VERSION,
} from './telemetryDisclosure';

function jsonResponse(data, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    statusText: ok ? 'OK' : 'Rejected',
    json: vi.fn().mockResolvedValue(data),
    text: vi.fn().mockResolvedValue(JSON.stringify(data)),
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, reject, resolve };
}

async function openTelemetryAdminPrompt(user) {
  expect(await screen.findByRole('heading', {
    name: 'Core telemetry gate is currently enabled',
  })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Manage in Settings' }));
  expect(await screen.findByRole('dialog', { name: 'Admin Access' })).toBeInTheDocument();
}

describe('App telemetry Settings authentication handoff', () => {
  beforeEach(() => {
    api.token = '';
    api.authFetch.mockReset().mockImplementation(async (url, options = {}) => {
      if (url === '/api/v1/settings/telemetry') {
        return jsonResponse({ effective: true, opt_in: true, source: 'persisted' });
      }
      if (url === '/api/v1/auth/setup-status') {
        return jsonResponse({ needs_setup_code: false, counts: { sensors: 1, devices: 1 } });
      }
      if (url === '/api/v1/auth/tokens' && options.method === 'POST') {
        return jsonResponse({ error: 'Setup code rejected by test Core' }, { ok: false, status: 401 });
      }
      if (url === '/api/v1/status') return jsonResponse({ scan: null });
      if (url === '/api/v1/devices') return jsonResponse({ devices: [] });
      return jsonResponse({});
    });
    api.authFetchJSON.mockReset();
    findings.canAdmin = false;
    findings.phase = 'healthy';
    findings.refresh.mockReset();
    findings.session = null;
    localStorage.clear();
  });

  it('keeps the disclosure blocking while a stored token session check hangs', async () => {
    api.token = 'stored-admin-test-token';
    findings.phase = 'loading';
    findings.session = null;
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole('heading', {
      name: 'Core telemetry gate is currently enabled',
    })).toBeInTheDocument();
    const inertApplication = document.querySelector('[inert]');
    expect(inertApplication).not.toBeNull();

    await user.click(screen.getByRole('button', { name: 'Manage in Settings' }));

    expect(screen.getByRole('heading', {
      name: 'Core telemetry gate is currently enabled',
    })).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Admin Access' })).not.toBeInTheDocument();
    expect(document.querySelector('[inert]')).toBe(inertApplication);
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();
  });

  it('keeps an initial-admin failure visible until explicit cancel restores the notice', async () => {
    const user = userEvent.setup();
    render(<App />);
    await openTelemetryAdminPrompt(user);

    await user.click(screen.getByRole('button', { name: 'Create Initial Admin Token' }));

    expect(await screen.findByText('Setup code rejected by test Core')).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Admin Access' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', {
      name: 'Core telemetry gate is currently enabled',
    })).not.toBeInTheDocument();
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();

    await user.click(screen.getByRole('button', { name: 'Close admin access dialog' }));
    expect(await screen.findByRole('heading', {
      name: 'Core telemetry gate is currently enabled',
    })).toBeInTheDocument();
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();
  });

  it('does not complete a cancelled Settings handoff after initial-admin creation succeeds', async () => {
    const creation = deferred();
    const response = jsonResponse({ token: 'late-created-admin-test-token' });
    const defaultAuthFetch = api.authFetch.getMockImplementation();
    api.authFetch.mockImplementation((url, options = {}) => {
      if (url === '/api/v1/auth/tokens' && options.method === 'POST') {
        return creation.promise;
      }
      return defaultAuthFetch(url, options);
    });
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    const user = userEvent.setup();
    render(<App />);
    await openTelemetryAdminPrompt(user);

    await user.click(screen.getByRole('button', { name: 'Create Initial Admin Token' }));
    expect(api.authFetch).toHaveBeenCalledWith(
      '/api/v1/auth/tokens',
      expect.objectContaining({ method: 'POST' }),
    );
    await user.click(screen.getByRole('button', { name: 'Close admin access dialog' }));
    expect(await screen.findByRole('heading', {
      name: 'Core telemetry gate is currently enabled',
    })).toBeInTheDocument();

    await act(async () => {
      creation.resolve(response);
      await creation.promise;
    });
    await waitFor(() => expect(response.json).toHaveBeenCalledTimes(1));

    expect(api.token).toBe('late-created-admin-test-token');
    expect(alertSpy).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('heading', { name: 'Settings' })).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Admin Access' })).not.toBeInTheDocument();
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();
    alertSpy.mockRestore();
  });

  it('keeps the application inert and focus trapped throughout Admin Access', async () => {
    const user = userEvent.setup();
    render(<App />);
    await openTelemetryAdminPrompt(user);

    const dialog = screen.getByRole('dialog', { name: 'Admin Access' });
    const inertApplication = document.querySelector('[inert]');
    expect(inertApplication).not.toBeNull();
    expect(inertApplication).not.toContainElement(dialog);
    expect(document.body.style.overflow).toBe('hidden');

    const first = screen.getByRole('button', { name: 'Close admin access dialog' });
    const last = screen.getByRole('button', { name: 'Use This Token' });
    last.focus();
    fireEvent.keyDown(last, { key: 'Tab' });
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });
    expect(last).toHaveFocus();

    await user.click(first);
    expect(await screen.findByRole('heading', {
      name: 'Core telemetry gate is currently enabled',
    })).toBeInTheDocument();
    expect(document.querySelector('[inert]')).not.toBeNull();
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();
  });

  it('restores the opener after ordinary Admin Access closes', async () => {
    localStorage.setItem(TELEMETRY_NOTICE_STORAGE_KEY, TELEMETRY_NOTICE_VERSION);
    const user = userEvent.setup();
    render(<App />);

    const opener = await screen.findByRole('button', { name: 'No admin token' });
    await user.click(opener);
    expect(await screen.findByRole('dialog', { name: 'Admin Access' })).toBeInTheDocument();
    expect(screen.getByRole('textbox', {
      name: 'Paste admin token (recovery / other device)',
    })).toHaveFocus();

    await user.click(screen.getByRole('button', { name: 'Close admin access dialog' }));
    expect(screen.queryByRole('dialog', { name: 'Admin Access' })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it('keeps invalid and read-only pasted-token errors visible for correction', async () => {
    const cases = [
      {
        name: 'invalid',
        response: () => api.authFetchJSON.mockRejectedValueOnce(new Error('Invalid test token')),
        message: 'Invalid test token',
      },
      {
        name: 'read-only',
        response: () => api.authFetchJSON.mockResolvedValueOnce({ authenticated: true, can_admin: false }),
        message: 'This token has read-only scope. An admin token is required to change telemetry.',
      },
    ];

    for (const testCase of cases) {
      localStorage.clear();
      api.token = '';
      testCase.response();
      const user = userEvent.setup();
      const view = render(<App />);
      await openTelemetryAdminPrompt(user);

      await user.type(screen.getByRole('textbox', { name: 'Paste admin token (recovery / other device)' }), `${testCase.name}-test-token`);
      await user.click(screen.getByRole('button', { name: 'Use This Token' }));

      expect(await screen.findByText(testCase.message)).toBeInTheDocument();
      expect(screen.getByRole('dialog', { name: 'Admin Access' })).toBeInTheDocument();
      expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();
      view.unmount();
    }
  });

  it('does not let stale useFindings scope bounce a directly verified admin from Settings', async () => {
    api.authFetchJSON.mockResolvedValueOnce({ authenticated: true, can_admin: true });
    const user = userEvent.setup();
    render(<App />);
    await openTelemetryAdminPrompt(user);

    await user.type(screen.getByRole('textbox', { name: 'Paste admin token (recovery / other device)' }), 'verified-admin-test-token');
    await user.click(screen.getByRole('button', { name: 'Use This Token' }));

    expect(await screen.findByRole('heading', { name: 'Settings' })).toBeInTheDocument();
    await waitFor(() => expect(document.getElementById('telemetry-settings')).toHaveFocus());
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBe(TELEMETRY_NOTICE_VERSION);
    expect(screen.queryByRole('dialog', { name: 'Admin Access' })).not.toBeInTheDocument();
  });

  it('ignores an older token validation that completes after a replacement submission', async () => {
    const first = deferred();
    const second = deferred();
    api.authFetchJSON
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const user = userEvent.setup();
    render(<App />);
    await openTelemetryAdminPrompt(user);

    const input = screen.getByRole('textbox', { name: 'Paste admin token (recovery / other device)' });
    await user.type(input, 'older-admin-test-token');
    await user.click(screen.getByRole('button', { name: 'Use This Token' }));
    await waitFor(() => expect(input).toHaveValue(''));

    await user.type(input, 'current-admin-test-token');
    await user.click(screen.getByRole('button', { name: 'Use This Token' }));
    expect(api.token).toBe('current-admin-test-token');

    await act(async () => {
      first.resolve({ authenticated: true, can_admin: true });
      await first.promise;
    });
    expect(screen.queryByRole('heading', { name: 'Settings' })).not.toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Admin Access' })).toBeInTheDocument();
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBeNull();
    expect(api.token).toBe('current-admin-test-token');

    await act(async () => {
      second.resolve({ authenticated: true, can_admin: true });
      await second.promise;
    });
    expect(await screen.findByRole('heading', { name: 'Settings' })).toBeInTheDocument();
    expect(localStorage.getItem(TELEMETRY_NOTICE_STORAGE_KEY)).toBe(TELEMETRY_NOTICE_VERSION);
  });
});
