import { authFetchJSON } from '../lib/api';

export function listActiveDeviceMerges() {
  return authFetchJSON('/api/v1/device-merges');
}

export function fetchDeviceThreatEvents(deviceID, { page = 1, limit = 100, minScore = 0.3 } = {}) {
  const params = new URLSearchParams({
    device_id: deviceID,
    min_score: String(minScore),
    page: String(page),
    limit: String(limit),
  });
  return authFetchJSON(`/api/v1/events?${params.toString()}`);
}

export function confirmDeviceIdentity(deviceID, { evidence, segment = '', sensorID = '', reason }) {
  return authFetchJSON(`/api/v1/devices/${encodeURIComponent(deviceID)}/confirm`, {
    method: 'POST',
    body: {
      evidence: {
        type: evidence.type,
        value: evidence.value,
        source: 'operator',
        confidence: 1,
        sensitive: Boolean(evidence.sensitive),
        display_value: evidence.sensitive ? '' : (evidence.display_value || evidence.value),
      },
      segment,
      sensor_id: sensorID,
      reason: reason.trim(),
    },
  });
}

export function mergeDevices(sourceDeviceID, targetDeviceID, reason) {
  return authFetchJSON('/api/v1/devices/merge', {
    method: 'POST',
    body: {
      source_device_id: sourceDeviceID,
      target_device_id: targetDeviceID,
      reason: reason.trim(),
    },
  });
}

export function splitDeviceMerge(actionID, reason) {
  return authFetchJSON(`/api/v1/device-merges/${encodeURIComponent(actionID)}/split`, {
    method: 'POST',
    body: { reason: reason.trim() },
  });
}
