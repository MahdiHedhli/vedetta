import { beforeEach, describe, expect, it, vi } from 'vitest';
import { authFetchJSON } from '../lib/api';
import { confirmDeviceIdentity, fetchDeviceThreatEvents, listActiveDeviceMerges, mergeDevices, splitDeviceMerge } from './api';

vi.mock('../lib/api', () => ({ authFetchJSON: vi.fn() }));

describe('identity action API contracts', () => {
  beforeEach(() => authFetchJSON.mockReset().mockResolvedValue({ action_id: 'audit-1' }));

  it('loads active merge audit projections', async () => {
    await listActiveDeviceMerges();
    expect(authFetchJSON).toHaveBeenCalledWith('/api/v1/device-merges');
  });

  it('queries device history by canonical identity instead of a global event sample', async () => {
    await fetchDeviceThreatEvents('device/canonical', { page: 2, limit: 100, minScore: 0.3 });
    expect(authFetchJSON).toHaveBeenCalledWith('/api/v1/events?device_id=device%2Fcanonical&min_score=0.3&page=2&limit=100');
  });

  it('sends confirmation evidence and its audit context', async () => {
    await confirmDeviceIdentity('device/source', {
      evidence: { type: 'mac', value: '00:00:5E:00:53:01', sensitive: true },
      segment: 'iot',
      sensorID: 'sensor-1',
      reason: '  Verified asset label  ',
    });
    expect(authFetchJSON).toHaveBeenCalledWith('/api/v1/devices/device%2Fsource/confirm', {
      method: 'POST',
      body: {
        evidence: {
          type: 'mac',
          value: '00:00:5E:00:53:01',
          source: 'operator',
          confidence: 1,
          sensitive: true,
          display_value: '',
        },
        segment: 'iot',
        sensor_id: 'sensor-1',
        reason: 'Verified asset label',
      },
    });
  });

  it('sends reversible merge and split reasons', async () => {
    await mergeDevices('source', 'target', ' Same physical device ');
    await splitDeviceMerge('merge/action', ' Incorrect merge ');
    expect(authFetchJSON).toHaveBeenNthCalledWith(1, '/api/v1/devices/merge', {
      method: 'POST',
      body: { source_device_id: 'source', target_device_id: 'target', reason: 'Same physical device' },
    });
    expect(authFetchJSON).toHaveBeenNthCalledWith(2, '/api/v1/device-merges/merge%2Faction/split', {
      method: 'POST',
      body: { reason: 'Incorrect merge' },
    });
  });
});
