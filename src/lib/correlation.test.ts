import { describe, it, expect } from 'vitest';
import {
  generateCorrelationId,
  getCorrelationContext,
  getCorrelationId,
  setProcessingStage,
  runWithCorrelation,
  runWithExistingCorrelation,
} from './correlation.js';

describe('Correlation Context', () => {
  describe('generateCorrelationId', () => {
    it('should generate a unique correlation ID with corr- prefix', () => {
      const id = generateCorrelationId();
      expect(id).toMatch(/^corr-[0-9a-f-]{36}$/);
    });

    it('should generate unique IDs on each call', () => {
      const id1 = generateCorrelationId();
      const id2 = generateCorrelationId();
      expect(id1).not.toBe(id2);
    });
  });

  describe('getCorrelationId outside context', () => {
    it('should return "none" when not in a correlation context', () => {
      expect(getCorrelationId()).toBe('none');
    });
  });

  describe('getCorrelationContext outside context', () => {
    it('should return undefined when not in a correlation context', () => {
      expect(getCorrelationContext()).toBeUndefined();
    });
  });

  describe('runWithCorrelation', () => {
    it('should set correlation context within the callback', () => {
      const corrId = generateCorrelationId();
      runWithCorrelation(corrId, () => {
        expect(getCorrelationId()).toBe(corrId);
        const ctx = getCorrelationContext();
        expect(ctx).toBeDefined();
        expect(ctx!.correlationId).toBe(corrId);
        expect(ctx!.stage).toBe('arrival');
        expect(ctx!.arrivalTimestamp).toBeGreaterThan(0);
      });
    });

    it('should return the function result', () => {
      const result = runWithCorrelation('corr-test', () => 42);
      expect(result).toBe(42);
    });

    it('should restore context after callback completes', () => {
      runWithCorrelation('corr-inner', () => {
        expect(getCorrelationId()).toBe('corr-inner');
      });
      expect(getCorrelationId()).toBe('none');
    });

    it('should support async callbacks', async () => {
      const corrId = generateCorrelationId();
      const result = await runWithCorrelation(corrId, async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return getCorrelationId();
      });
      expect(result).toBe(corrId);
    });

    it('should maintain context through nested async operations', async () => {
      const corrId = generateCorrelationId();
      await runWithCorrelation(corrId, async () => {
        const id1 = getCorrelationId();
        await new Promise((resolve) => setTimeout(resolve, 1));
        const id2 = getCorrelationId();
        expect(id1).toBe(corrId);
        expect(id2).toBe(corrId);
      });
    });
  });

  describe('setProcessingStage', () => {
    it('should update the stage in an active context', () => {
      runWithCorrelation('corr-stage', () => {
        expect(getCorrelationContext()!.stage).toBe('arrival');
        setProcessingStage('guard-check');
        expect(getCorrelationContext()!.stage).toBe('guard-check');
        setProcessingStage('risk-scoring');
        expect(getCorrelationContext()!.stage).toBe('risk-scoring');
      });
    });

    it('should not throw when called outside a context', () => {
      expect(() => setProcessingStage('completed')).not.toThrow();
    });
  });

  describe('runWithExistingCorrelation', () => {
    it('should run with a provided context object', () => {
      const ctx = {
        correlationId: 'corr-existing',
        arrivalTimestamp: Date.now() - 100,
        stage: 'threat-intel' as const,
      };
      runWithExistingCorrelation(ctx, () => {
        expect(getCorrelationId()).toBe('corr-existing');
        expect(getCorrelationContext()!.stage).toBe('threat-intel');
      });
    });
  });

  describe('concurrent correlation contexts', () => {
    it('should isolate contexts between concurrent async operations', async () => {
      const results: string[] = [];
      const p1 = runWithCorrelation('corr-1', async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        results.push(getCorrelationId());
      });
      const p2 = runWithCorrelation('corr-2', async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        results.push(getCorrelationId());
      });
      await Promise.all([p1, p2]);
      expect(results).toContain('corr-1');
      expect(results).toContain('corr-2');
    });
  });
});
