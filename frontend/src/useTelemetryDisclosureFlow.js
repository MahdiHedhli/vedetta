import { useCallback, useEffect, useRef, useState } from 'react';
import {
  persistTelemetryNoticeAcknowledgement,
  telemetryNoticeAcknowledged,
} from './telemetryDisclosure';

// The Settings link is a deferred acknowledgement: merely asking to manage the
// setting must not dismiss the notice permanently. The acknowledgement is only
// stored after the operator explicitly continues or reaches the authoritative
// admin-only Settings destination.
export function useTelemetryDisclosureFlow(storage) {
  const pendingSettingsRef = useRef(false);
  const [state, setState] = useState(() => ({
    showNotice: !telemetryNoticeAcknowledged(storage),
    settingsHandoffPending: false,
  }));

  const acknowledge = useCallback(() => {
    persistTelemetryNoticeAcknowledgement(storage);
    pendingSettingsRef.current = false;
    setState({ showNotice: false, settingsHandoffPending: false });
  }, [storage]);

  const beginSettingsHandoff = useCallback(() => {
    pendingSettingsRef.current = true;
    setState({ showNotice: false, settingsHandoffPending: true });
  }, []);

  const completeSettingsHandoff = useCallback(() => {
    if (pendingSettingsRef.current) {
      persistTelemetryNoticeAcknowledgement(storage);
    }
    pendingSettingsRef.current = false;
    setState({ showNotice: false, settingsHandoffPending: false });
  }, [storage]);

  const cancelSettingsHandoff = useCallback(() => {
    const restoreNotice = pendingSettingsRef.current;
    pendingSettingsRef.current = false;
    setState((current) => ({
      showNotice: restoreNotice ? true : current.showNotice,
      settingsHandoffPending: false,
    }));
  }, []);

  return {
    showTelemetryNotice: state.showNotice,
    settingsHandoffPending: state.settingsHandoffPending,
    acknowledgeTelemetry: acknowledge,
    beginTelemetrySettingsHandoff: beginSettingsHandoff,
    completeTelemetrySettingsHandoff: completeSettingsHandoff,
    cancelTelemetrySettingsHandoff: cancelSettingsHandoff,
  };
}

// The admin prompt can already be mounted behind the inert telemetry notice
// after a background 401. Its input therefore needs an explicit focus handoff
// when the notice becomes hidden; mount-only autoFocus cannot cover that case.
export function useAdminPromptFocus({
  promptVisible,
  blockingNoticeVisible,
  preferSetupCode,
  setupCodeRef,
  tokenInputRef,
  fallbackRef,
}) {
  useEffect(() => {
    if (!promptVisible || blockingNoticeVisible) return;
    const target = (preferSetupCode ? setupCodeRef.current : tokenInputRef.current)
      || tokenInputRef.current
      || fallbackRef.current;
    target?.focus();
  }, [
    blockingNoticeVisible,
    fallbackRef,
    preferSetupCode,
    promptVisible,
    setupCodeRef,
    tokenInputRef,
  ]);
}

// Keeps a blocking dialog modal for keyboard and pointer users: the application
// subtree is made inert by the caller, while this hook locks body scrolling,
// traps Tab within the dialog rendered beside that subtree, and restores the
// prior focus when the dialog closes (when the prior node still exists).
export function useBlockingDialogFocus({ active, dialogRef }) {
  const previousFocusRef = useRef(null);

  useEffect(() => {
    if (!active) return undefined;
    previousFocusRef.current = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const onKeyDown = (event) => {
      if (event.key !== 'Tab') return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(dialog.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const current = document.activeElement;
      if (!dialog.contains(current) || !focusable.includes(current)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && current === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && current === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      document.body.style.overflow = previousOverflow;
      const previous = previousFocusRef.current;
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
  }, [active, dialogRef]);
}
