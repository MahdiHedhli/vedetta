import { useEffect, useReducer, useState } from 'react';
import { authFetch } from './lib/api';

// UpdateNotice shows a dismissible banner when the backend reports that a newer Vedetta
// software release (v*) or signed device-DB release (db-*) is available. It is read-only —
// it renders whatever /api/v1/update-status reports and never triggers an update. A dismissal
// is remembered per release tag, so a brand-new release surfaces again.

const DISMISS_PREFIX = 'vedetta_update_dismissed:';
export const UPDATE_STATUS_POLL_MS = 15 * 60 * 1000;

function dismissKey(kind, tag) {
  return `${DISMISS_PREFIX}${kind}:${tag}`;
}

function isDismissed(kind, tag) {
  try {
    return localStorage.getItem(dismissKey(kind, tag)) === '1';
  } catch {
    return false;
  }
}

function rememberDismissed(kind, tag) {
  try {
    localStorage.setItem(dismissKey(kind, tag), '1');
  } catch {
    // A full/blocked localStorage just means the notice reappears next load — acceptable.
  }
}

export default function UpdateNotice({ authRefreshKey = '' }) {
  const [status, setStatus] = useState(null);
  const [, forceRender] = useReducer((x) => x + 1, 0);

  useEffect(() => {
    let alive = true;
    let inFlight = false;
    const refresh = () => {
      if (inFlight) return;
      inFlight = true;
      authFetch('/api/v1/update-status')
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (alive && data) setStatus(data);
        })
        .catch(() => {
          /* a failed check simply keeps the last visible notice state */
        })
        .finally(() => {
          inFlight = false;
        });
    };
    refresh();
    const timer = window.setInterval(refresh, UPDATE_STATUS_POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [authRefreshKey]);

  if (!status || !status.enabled) return null;

  const notices = [];
  const sw = status.software;
  if (sw && sw.update_available && sw.latest && !isDismissed('software', sw.latest)) {
    notices.push({
      kind: 'software',
      tag: sw.latest,
      text: sw.current
        ? `Vedetta ${sw.latest} is available — you're running ${sw.current}.`
        : `Vedetta ${sw.latest} is available.`,
      url: sw.url,
    });
  }
  const db = status.device_db;
  if (db && db.update_available && db.latest && !isDismissed('devicedb', db.latest)) {
    notices.push({
      kind: 'devicedb',
      tag: db.latest,
      text: `A newer device database (${db.latest}) is available.`,
      url: db.url,
    });
  }
  if (notices.length === 0) return null;

  return (
    <div className="space-y-2" data-testid="update-notice">
      {notices.map((n) => (
        <div
          key={n.kind}
          role="status"
          className="flex items-center justify-between gap-3 rounded border border-blue-700 bg-blue-950/60 px-4 py-2 text-sm text-blue-100"
        >
          <span>
            {n.text}
            {n.url && (
              <a
                href={n.url}
                target="_blank"
                rel="noopener noreferrer"
                className="ml-2 underline hover:text-white"
              >
                Release notes
              </a>
            )}
          </span>
          <button
            type="button"
            aria-label={
              n.kind === 'software'
                ? 'Dismiss Vedetta software update notice'
                : 'Dismiss device database update notice'
            }
            className="shrink-0 text-blue-300 hover:text-white"
            onClick={() => {
              rememberDismissed(n.kind, n.tag);
              forceRender();
            }}
          >
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}
