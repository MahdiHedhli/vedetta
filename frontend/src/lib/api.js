// frontend/src/lib/api.js
// Minimal authenticated fetch wrapper + admin token management for Vedetta dashboard.
//
// Design goals for alpha:
// - Zero config on fresh install (bootstrap mode)
// - Simple localStorage-backed admin token
// - Easy recovery: user can paste an existing admin token
// - All existing fetch calls can migrate to authFetch with minimal diff

const TOKEN_KEY = 'vedetta_admin_token';

export function getAdminToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setAdminToken(token) {
  try {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token.trim());
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // localStorage may be unavailable (private mode, etc.)
  }
}

export function clearAdminToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {}
}

export function hasAdminToken() {
  return !!getAdminToken();
}

/**
 * authFetch — drop-in replacement for fetch that automatically adds
 * the Authorization header when an admin token is present.
 *
 * Usage:
 *   authFetch('/api/v1/devices').then(r => r.json())
 *   authFetch('/api/v1/suppression', { method: 'POST', body: JSON.stringify(...) })
 */
export async function authFetch(url, options = {}) {
  const token = getAdminToken();
  const headers = new Headers(options.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  // Ensure JSON content-type for POST/PUT when body is object
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    options.body = JSON.stringify(options.body);
  }

  const finalOptions = {
    ...options,
    headers,
  };

  const response = await fetch(url, finalOptions);

  // Global 401 handling hook (UI can listen via a custom event if desired)
  if (response.status === 401) {
    // Token is invalid or expired — let the app decide what to do
    window.dispatchEvent(new CustomEvent('vedetta:auth:unauthorized', { detail: { url } }));
  }

  return response;
}

/**
 * Convenience helper for JSON responses.
 * Throws on non-2xx so callers can use try/catch.
 */
export async function authFetchJSON(url, options = {}) {
  const res = await authFetch(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`HTTP ${res.status}: ${text || res.statusText}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// Expose on window for quick debugging in devtools if needed
if (typeof window !== 'undefined') {
  window.__vedettaAuth = { getAdminToken, setAdminToken, clearAdminToken, authFetch };
}
