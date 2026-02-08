import { describe, it, expect, beforeEach } from 'vitest';
import { WebhookArrivalTimes } from './webhook-arrival-times.js';

describe('WebhookArrivalTimes', () => {
  let times: WebhookArrivalTimes;

  beforeEach(() => {
    times = new WebhookArrivalTimes();
  });

  describe('record and consume', () => {
    it('should store and retrieve an arrival time', () => {
      const now = Date.now();
      times.record('msg-1', now);
      expect(times.consume('msg-1')).toBe(now);
    });

    it('should remove entry after consume', () => {
      times.record('msg-1', Date.now());
      times.consume('msg-1');
      expect(times.consume('msg-1')).toBeUndefined();
    });

    it('should return undefined for unknown message ID', () => {
      expect(times.consume('unknown')).toBeUndefined();
    });

    it('should handle multiple message IDs', () => {
      const t1 = Date.now();
      const t2 = t1 + 100;
      times.record('msg-1', t1);
      times.record('msg-2', t2);

      expect(times.consume('msg-1')).toBe(t1);
      expect(times.consume('msg-2')).toBe(t2);
    });
  });

  describe('size', () => {
    it('should report correct size', () => {
      expect(times.size).toBe(0);
      times.record('msg-1', Date.now());
      expect(times.size).toBe(1);
      times.record('msg-2', Date.now());
      expect(times.size).toBe(2);
    });

    it('should decrease after consume', () => {
      times.record('msg-1', Date.now());
      times.consume('msg-1');
      expect(times.size).toBe(0);
    });
  });

  describe('clear', () => {
    it('should remove all entries', () => {
      times.record('msg-1', Date.now());
      times.record('msg-2', Date.now());
      times.clear();
      expect(times.size).toBe(0);
      expect(times.consume('msg-1')).toBeUndefined();
    });
  });

  describe('overflow protection', () => {
    it('should handle many entries without error', () => {
      for (let i = 0; i < 100; i++) {
        times.record(`msg-${i}`, Date.now());
      }
      expect(times.size).toBe(100);
      expect(times.consume('msg-50')).toBeDefined();
    });
  });
});
