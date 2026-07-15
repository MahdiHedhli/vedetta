import React, { useEffect, useRef } from 'react';

const PRIVACY_NOTICE_URL = 'https://github.com/MahdiHedhli/vedetta/blob/main/PRIVACY.md';

export function TelemetryInertBackground({ active, children }) {
  return (
    <div
      className="min-h-screen"
      inert={active ? '' : undefined}
      aria-hidden={active ? 'true' : undefined}
    >
      {children}
    </div>
  );
}

function TelemetryPrivacyBoundary({ conditional = false }) {
  return (
    <>
      <p>
        {conditional ? 'When telemetry is enabled, each beta signal is' : 'Each beta signal is'} a
        Core-confirmed known-bad hit: the matched public block-list domain and its eTLD+1, an hourly
        event bucket, observation/distinct-asset/blocked counts, local confidence, and fixed reason
        codes. The signed envelope also carries random signal and batch IDs, schema version, and
        batch-generation and collection-window timestamps.
      </p>
      <p>
        Registration sends a random install UUID, the Vedetta version, and supported capability
        names. The service does not retain that install UUID; it issues a stable reporter ID and
        stores that pseudonym with version/capability data, creation and last-seen times, signal
        data with exact receipt/first-received/last-merge times, and batch receipt counts. Signal
        rows and batch receipts expire after 30 days, but reporter and derived-record expiry is
        incomplete. Cloudflare observes the public connection address and timing; the community
        service also holds that address and its last-access time only in an in-memory rate-limit
        bucket while active and until swept after 30 idle minutes. It is not written to SQLite or
        application logs. This is pseudonymous, not anonymous.
      </p>
      <p>
        No internal/device IP, MAC, hostname, raw query, or per-asset hash is sent; the local HMAC
        is reduced to the distinct-asset count before export. {conditional
          ? 'When disabled, telemetry stops contributions only.'
          : 'Turning telemetry off stops contributions only.'}{' '}
        Local monitoring and public threat-feed downloads continue normally; fewer contributions
        may slow community improvements overall.
      </p>
    </>
  );
}

function DisclosureCopy({ phase, setting }) {
  if (phase === 'loading') {
    return (
      <div id="telemetry-ack-description" className="space-y-3 text-sm text-gray-300 leading-relaxed">
        <p>Vedetta is checking this Core's effective telemetry setting before describing its current state.</p>
      </div>
    );
  }

  return (
    <div id="telemetry-ack-description" className="space-y-3 text-sm text-gray-300 leading-relaxed">
      {phase === 'error' ? (
        <>
          <p>
            This browser could not verify this Core's effective telemetry setting. Its current state
            is unknown; do not infer that contribution is either enabled or disabled.
          </p>
          <TelemetryPrivacyBoundary conditional />
          <p>
            Verify or change the setting in Settings. You can also set{' '}
            <code className="text-gray-200">VEDETTA_TELEMETRY_OPTIN=false</code> and restart to opt out.
          </p>
        </>
      ) : setting?.effective === false ? (
        <>
          <p>
            Pseudonymous telemetry is currently disabled on this Core. No community contributions
            are sent while it remains disabled.
          </p>
          <TelemetryPrivacyBoundary conditional />
        </>
      ) : (
        <>
          <p>Pseudonymous telemetry is enabled on this Core.</p>
          <TelemetryPrivacyBoundary />
        </>
      )}
    </div>
  );
}

export function TelemetryAcknowledgementDialog({
  phase,
  setting,
  onAcknowledge,
  onManageSettings,
  onRetry,
}) {
  const dialogRef = useRef(null);
  const primaryRef = useRef(null);
  const previousFocusRef = useRef(null);
  const restoreFocusRef = useRef(true);

  useEffect(() => {
    previousFocusRef.current = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const onKeyDown = (event) => {
      if (event.key !== 'Tab') return;
      const node = dialogRef.current;
      if (!node) return;
      const focusable = Array.from(node.querySelectorAll(
        'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      if (focusable.length === 0) {
        event.preventDefault();
        node.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (!node.contains(active) || !focusable.includes(active)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      document.body.style.overflow = previousOverflow;
      const previous = previousFocusRef.current;
      if (restoreFocusRef.current && previous instanceof HTMLElement && previous.isConnected) {
        previous.focus();
      }
    };
  }, []);

  useEffect(() => {
    if (phase === 'loading') dialogRef.current?.focus();
    else primaryRef.current?.focus();
  }, [phase]);

  const manageSettings = () => {
    restoreFocusRef.current = false;
    onManageSettings();
  };

  const isLoading = phase === 'loading';
  const title = isLoading
    ? 'Checking telemetry status'
    : phase === 'error'
      ? 'Telemetry status could not be verified'
      : setting?.effective === false
        ? 'Telemetry is currently disabled'
        : 'Pseudonymous telemetry is currently enabled';

  return (
    <div
      ref={dialogRef}
      className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-[60] p-4 overflow-y-auto overscroll-contain"
      role="dialog"
      aria-modal="true"
      aria-labelledby="telemetry-ack-title"
      aria-describedby="telemetry-ack-description"
      tabIndex={-1}
    >
      <div className="bg-gray-900 border border-amber-900/50 rounded-2xl max-w-lg w-full p-6 sm:p-8 space-y-5 shadow-2xl max-h-[90dvh] overflow-y-auto overscroll-contain my-auto">
        <div className="flex items-start gap-3">
          <svg aria-hidden="true" className="w-6 h-6 text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h2 id="telemetry-ack-title" className="text-lg font-semibold text-white leading-snug">
            {title}
          </h2>
        </div>

        <DisclosureCopy phase={phase} setting={setting} />

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pt-1">
          <div className="text-xs text-gray-500">
            {!isLoading && (
              <>
                <button onClick={manageSettings} className="underline hover:text-gray-300">
                  Manage in Settings
                </button>
                {' · '}
              </>
            )}
            <a
              href={PRIVACY_NOTICE_URL}
              target="_blank"
              rel="noreferrer"
              className="underline hover:text-gray-300"
            >
              Read our Privacy Notice
            </a>
            {phase === 'error' && (
              <>
                {' · '}
                <button onClick={onRetry} className="underline hover:text-gray-300">Retry status check</button>
              </>
            )}
          </div>
          <button
            ref={primaryRef}
            onClick={onAcknowledge}
            disabled={isLoading}
            className="bg-amber-600 hover:bg-amber-500 text-white font-medium text-sm px-6 py-2.5 rounded-lg transition-colors flex-shrink-0 tracking-wide disabled:opacity-50 disabled:cursor-wait"
          >
            {isLoading ? 'CHECKING…' : phase === 'error' || setting?.effective === false ? 'CONTINUE' : 'ACKNOWLEDGED'}
          </button>
        </div>
      </div>
    </div>
  );
}
