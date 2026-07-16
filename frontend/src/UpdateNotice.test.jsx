import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import UpdateNotice from './UpdateNotice';

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
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss update notice' }));
    await waitFor(() =>
      expect(screen.queryByText(/Vedetta v1\.3\.0 is available/)).not.toBeInTheDocument(),
    );
    expect(localStorage.getItem('vedetta_update_dismissed:software:v1.3.0')).toBe('1');
  });
});
