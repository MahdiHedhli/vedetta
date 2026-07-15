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
