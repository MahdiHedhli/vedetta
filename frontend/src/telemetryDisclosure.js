export const TELEMETRY_NOTICE_STORAGE_KEY = 'vedetta_telemetry_notice_ack';
export const TELEMETRY_NOTICE_VERSION = '2';
export const TELEMETRY_STATUS_UNAVAILABLE_MESSAGE =
  "Core's effective telemetry state could not be verified; it is unknown, so do not infer enabled or disabled.";

export function telemetryNoticeAcknowledged(storage) {
  try {
    const target = storage === undefined ? globalThis.localStorage : storage;
    return target?.getItem(TELEMETRY_NOTICE_STORAGE_KEY) === TELEMETRY_NOTICE_VERSION;
  } catch {
    return false;
  }
}

export function persistTelemetryNoticeAcknowledgement(storage) {
  try {
    const target = storage === undefined ? globalThis.localStorage : storage;
    if (!target) return false;
    target.setItem(TELEMETRY_NOTICE_STORAGE_KEY, TELEMETRY_NOTICE_VERSION);
    return true;
  } catch {
    return false;
  }
}

export async function readTelemetryDisclosureSetting(fetchImpl, { signal } = {}) {
  const response = await fetchImpl('/api/v1/settings/telemetry', { signal });
  if (!response.ok) {
    const error = new Error(`Telemetry status is unavailable (HTTP ${response.status})`);
    error.status = response.status;
    throw error;
  }

  const data = await response.json();
  if (typeof data?.effective !== 'boolean') {
    throw new Error('Telemetry status response did not include an effective setting');
  }
  return data;
}

// A stored token is not proof of admin scope. Wait while /auth/session is still
// loading, then either navigate on authoritative admin confirmation or prompt.
export function telemetrySettingsAccessAction({ canAdmin, tokenPresent, session, phase }) {
  if (!tokenPresent) return 'prompt';
  if (canAdmin && session?.authenticated === true && session?.can_admin === true) return 'navigate';
  if (session !== null || phase !== 'loading') return 'prompt';
  return 'wait';
}
