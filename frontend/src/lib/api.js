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

// urlStringFromInput extracts a plain-string URL from any value fetch() accepts
// as its first argument: a string, a URL instance, or a Request instance. It
// returns null for anything else (or when extraction is unsafe) so the caller
// can FAIL CLOSED — an input we cannot classify must never receive the Core
// bearer. This never throws.
function urlStringFromInput(input) {
  try {
    if (typeof input === 'string') return input;
    // A URL instance exposes the absolute URL via .href.
    if (typeof URL !== 'undefined' && input instanceof URL) {
      return typeof input.href === 'string' ? input.href : null;
    }
    // A Request instance exposes its already-resolved absolute URL via .url.
    if (typeof Request !== 'undefined' && input instanceof Request) {
      return typeof input.url === 'string' ? input.url : null;
    }
    return null;
  } catch {
    return null;
  }
}

// Join CORE_BASE with a relative Core path. Absolute URLs are returned as-is
// so callers that already build a full URL keep working. Non-string inputs
// (URL/Request) are returned untouched so fetch() receives them natively; the
// origin gate operates on the extracted string form (see urlStringFromInput),
// never on the raw object, so this never needs to throw.
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
  try {
    if (typeof window === 'undefined' || !window.location) return false;
    const loc = window.location;
    // Core origin: explicit CORE_BASE (resolved against the real page URL, never
    // an injected <base>), else the page's own origin.
    const base = CORE_BASE ? new URL(CORE_BASE, loc.href) : new URL(loc.origin);
    // Resolve the target EXACTLY as fetch() will: fetch resolves a relative URL
    // against document.baseURI, so anchoring here to baseURI (not location.href)
    // stops an injected <base href> from making the gate and the real request
    // target disagree (GHSA-cm6m hardening).
    const resolveBase = (typeof document !== 'undefined' && document.baseURI) || loc.href;
    const target = new URL(resolvedUrl, resolveBase);
    return target.origin === base.origin;
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

  // The origin gate must run on a plain-string URL, whatever fetch-input shape
  // the caller passed (string / URL / Request). Extract that string first; if we
  // cannot (unknown/unsupported type), urlStr is null and we FAIL CLOSED — the
  // Core bearer is only ever attached to a resolved string whose origin equals
  // the Core origin. This makes authFetch(new Request('http://external/...'))
  // safe by construction: its origin is not Core, so no bearer is attached, and
  // an unclassifiable input likewise gets none. (GHSA-cm6m residual hardening.)
  const urlStr = urlStringFromInput(url);
  if (
    token &&
    !headers.has('Authorization') &&
    urlStr !== null &&
    isCoreUrl(urlStr, resolveCoreUrl(urlStr))
  ) {
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
