// frontend/src/lib/api.js
// Minimal authenticated fetch wrapper + admin token management for Vedetta dashboard.
//
// Design goals for alpha:
// - Zero config on fresh install (bootstrap mode)
// - Simple localStorage-backed admin token
// - Easy recovery: user can paste an existing admin token
// - All existing fetch calls can migrate to authFetch with minimal diff

const TOKEN_KEY = 'vedetta_admin_token';

// Centralized base URL for the Vedetta Core API. Empty string = same origin
// (relative /api/... paths, proxied by Vite in dev and nginx in prod).
// Override at build time with VITE_CORE_BASE for split-origin deployments.
export const CORE_BASE =
  (typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.VITE_CORE_BASE) ||
  '';

// Join CORE_BASE with a relative Core path. Absolute URLs are returned as-is
// so callers that already build a full URL keep working.
function resolveCoreUrl(url) {
  if (typeof url !== 'string') return url;
  if (/^https?:\/\//i.test(url)) return url;
  return `${CORE_BASE}${url}`;
}

// isCoreUrl reports whether a request will hit the Vedetta Core API, so the Core
// bearer is only ever attached to Core-origin requests. A relative path always
// targets Core (same origin, or CORE_BASE); an absolute URL qualifies only when
// it shares CORE_BASE's origin (or, when CORE_BASE is empty, the page's own
// origin). This makes leaking the Core token to a third-party host (e.g. the
// community threat-network/feed) structurally impossible rather than relying on
// every caller to only pass relative paths.
function isCoreUrl(rawUrl, resolvedUrl) {
  if (typeof rawUrl === 'string' && !/^https?:\/\//i.test(rawUrl)) return true;
  try {
    const here =
      (typeof window !== 'undefined' && window.location && window.location.href) || undefined;
    const target = new URL(resolvedUrl, here);
    const base = CORE_BASE ? new URL(CORE_BASE, here) : here ? new URL(here) : null;
    return !!base && target.origin === base.origin;
  } catch {
    return false;
  }
}

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
  const resolvedUrl = resolveCoreUrl(url);

  // Only ever attach the Core bearer to a Core-origin request (see isCoreUrl).
  if (token && !headers.has('Authorization') && isCoreUrl(url, resolvedUrl)) {
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

  const response = await fetch(resolvedUrl, finalOptions);

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
