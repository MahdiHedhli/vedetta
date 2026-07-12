export function stableDeviceID(record = {}) {
  return record.canonical_device_id || record.device_id || '';
}

// Raw-event clustering follows the same stable identity rules as findings. An
// unresolved event may still be grouped by Core's local pseudonym plus its
// authenticated collection context, but never by the current IP projection.
export function eventAssetKey(record = {}) {
  const deviceID = stableDeviceID(record);
  if (deviceID) return `device:${deviceID}`;

  const sourceHash = String(record.source_hash || '').trim();
  if (sourceHash && sourceHash !== 'unknown') {
    return `unresolved:${sourceHash}:${record.sensor_id || ''}:${record.network_segment || 'default'}`;
  }
  return `event:${record.event_id || 'unknown'}`;
}

// blocked=false is not proof that traffic was allowed: passive DNS and generic
// observations have no enforcement point. Core now persists an explicit
// outcome; legacy rows without one are conservatively presented as observed.
export function eventOutcome(record = {}) {
  const outcome = String(record.outcome || '').trim().toLowerCase();
  if (outcome === 'blocked' || outcome === 'allowed' || outcome === 'observed') return outcome;
  return record.blocked === true ? 'blocked' : 'observed';
}

// Event history follows the stable/canonical asset identity supplied by Core.
// A current IP address is intentionally never a fallback: address reuse would
// attach another device's historical evidence to the selected asset.
export function eventBelongsToDevice(event, device) {
  const eventID = stableDeviceID(event);
  const deviceID = stableDeviceID(device);
  return Boolean(eventID && deviceID && eventID === deviceID);
}
