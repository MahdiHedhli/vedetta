import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { authFetch, getAdminToken, setAdminToken } from './api';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, reject, resolve };
}

describe('authFetch unauthorized response ordering', () => {
  beforeEach(() => {
    setAdminToken('');
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    setAdminToken('');
    vi.unstubAllGlobals();
  });

  it('does not invalidate a newly stored token for a late tokenless 401', async () => {
    const response = deferred();
    fetch.mockReturnValueOnce(response.promise);
    const unauthorized = vi.fn();
    window.addEventListener('vedetta:auth:unauthorized', unauthorized);
    try {
      const request = authFetch('/api/v1/status');
      setAdminToken('new-test-token');
      response.resolve({ status: 401 });
      await request;

      expect(unauthorized).not.toHaveBeenCalled();
      expect(getAdminToken()).toBe('new-test-token');
    } finally {
      window.removeEventListener('vedetta:auth:unauthorized', unauthorized);
    }
  });

  it('does not invalidate a replacement token for an older bearer 401', async () => {
    setAdminToken('old-test-token');
    const response = deferred();
    fetch.mockReturnValueOnce(response.promise);
    const unauthorized = vi.fn();
    window.addEventListener('vedetta:auth:unauthorized', unauthorized);
    try {
      const request = authFetch('/api/v1/status');
      expect(fetch.mock.calls[0][1].headers.get('Authorization')).toBe('Bearer old-test-token');
      setAdminToken('replacement-test-token');
      response.resolve({ status: 401 });
      await request;

      expect(unauthorized).not.toHaveBeenCalled();
      expect(getAdminToken()).toBe('replacement-test-token');
    } finally {
      window.removeEventListener('vedetta:auth:unauthorized', unauthorized);
    }
  });

  it('still reports a 401 for the currently stored Core bearer', async () => {
    setAdminToken('current-test-token');
    fetch.mockResolvedValueOnce({ status: 401 });
    const unauthorized = vi.fn();
    window.addEventListener('vedetta:auth:unauthorized', unauthorized);
    try {
      await authFetch('/api/v1/status');
      expect(unauthorized).toHaveBeenCalledTimes(1);
      expect(getAdminToken()).toBe('current-test-token');
    } finally {
      window.removeEventListener('vedetta:auth:unauthorized', unauthorized);
    }
  });
});
