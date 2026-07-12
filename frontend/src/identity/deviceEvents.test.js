import { describe, expect, it } from 'vitest';
import { eventAssetKey, eventBelongsToDevice, eventOutcome } from './deviceEvents';

describe('device event history identity', () => {
  it('survives an address change when stable identity agrees', () => {
    const device = { device_id: 'camera-1', ip_address: '192.0.2.99' };
    const event = { device_id: 'camera-1', source_ip: '192.0.2.10' };
    expect(eventBelongsToDevice(event, device)).toBe(true);
  });

  it('never attaches history from a reused current IP without stable identity', () => {
    const device = { device_id: 'camera-1', ip_address: '192.0.2.99' };
    const oldTenant = { device_id: 'laptop-2', source_ip: '192.0.2.99' };
    const unresolved = { source_ip: '192.0.2.99' };
    expect(eventBelongsToDevice(oldTenant, device)).toBe(false);
    expect(eventBelongsToDevice(unresolved, device)).toBe(false);
  });

  it('uses canonical merge targets on both sides', () => {
    const device = { device_id: 'source-device', canonical_device_id: 'canonical-device' };
    const event = { device_id: 'other-source', canonical_device_id: 'canonical-device' };
    expect(eventBelongsToDevice(event, device)).toBe(true);
  });

  it('clusters by stable identity and never by a reused current IP', () => {
    expect(eventAssetKey({ device_id: 'camera-1', source_ip: '192.0.2.10' })).toBe('device:camera-1');
    expect(eventAssetKey({ device_id: 'camera-1', source_ip: '192.0.2.99' })).toBe('device:camera-1');
    expect(eventAssetKey({ source_hash: 'local-hash', sensor_id: 'sensor-a', network_segment: 'iot' }))
      .toBe('unresolved:local-hash:sensor-a:iot');
    expect(eventAssetKey({ event_id: 'event-a', source_ip: '192.0.2.10' })).toBe('event:event-a');
    expect(eventAssetKey({ event_id: 'event-b', source_ip: '192.0.2.10' })).toBe('event:event-b');
  });

  it('does not infer allowed from a passive blocked=false observation', () => {
    expect(eventOutcome({ blocked: false })).toBe('observed');
    expect(eventOutcome({ outcome: 'observed', blocked: false })).toBe('observed');
    expect(eventOutcome({ outcome: 'allowed', blocked: false })).toBe('allowed');
    expect(eventOutcome({ blocked: true })).toBe('blocked');
  });
});
