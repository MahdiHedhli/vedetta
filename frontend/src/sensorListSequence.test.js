import { describe, expect, it } from 'vitest';
import { sensorListFailureWatermark } from './App';

describe('sensor list request sequencing', () => {
  it('invalidates older in-flight polls when a post-mutation refresh fails', () => {
    expect(sensorListFailureWatermark(1, 3, true)).toBe(3);
  });

  it('never moves the applied watermark backwards', () => {
    expect(sensorListFailureWatermark(4, 2, true)).toBe(4);
  });

  it('lets an older response remain eligible after a background poll failure', () => {
    expect(sensorListFailureWatermark(1, 3, false)).toBe(1);
  });
});
