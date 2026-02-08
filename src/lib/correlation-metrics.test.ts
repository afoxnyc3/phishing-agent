import { describe, it, expect, beforeEach } from 'vitest';
import { CorrelationMetrics } from './correlation-metrics.js';

describe('CorrelationMetrics', () => {
  let cm: CorrelationMetrics;

  beforeEach(() => {
    cm = new CorrelationMetrics();
  });

  describe('analysisDuration', () => {
    it('should record and retrieve analysis durations', () => {
      cm.recordAnalysisDuration(100);
      cm.recordAnalysisDuration(200);
      cm.recordAnalysisDuration(300);

      const snap = cm.getSnapshot();
      expect(snap.analysisDurations.count).toBe(3);
      expect(snap.analysisDurations.p50).toBe(200);
    });

    it('should calculate p95 and p99 percentiles', () => {
      for (let i = 1; i <= 100; i++) {
        cm.recordAnalysisDuration(i);
      }
      const snap = cm.getSnapshot();
      expect(snap.analysisDurations.p95).toBe(95);
      expect(snap.analysisDurations.p99).toBe(99);
    });

    it('should return 0 for empty durations', () => {
      const snap = cm.getSnapshot();
      expect(snap.analysisDurations.p50).toBe(0);
      expect(snap.analysisDurations.count).toBe(0);
    });

    it('should limit to 1000 samples', () => {
      for (let i = 0; i < 1200; i++) {
        cm.recordAnalysisDuration(i);
      }
      const snap = cm.getSnapshot();
      expect(snap.analysisDurations.count).toBeLessThanOrEqual(1000);
    });
  });

  describe('riskScore', () => {
    it('should record and compute risk score distribution', () => {
      cm.recordRiskScore(2.0);
      cm.recordRiskScore(5.0);
      cm.recordRiskScore(8.0);

      const snap = cm.getSnapshot();
      expect(snap.riskScoreDistribution.count).toBe(3);
      expect(snap.riskScoreDistribution.p50).toBe(5.0);
      expect(snap.riskScoreDistribution.mean).toBe(5);
    });

    it('should handle single score', () => {
      cm.recordRiskScore(7.5);
      const snap = cm.getSnapshot();
      expect(snap.riskScoreDistribution.p50).toBe(7.5);
      expect(snap.riskScoreDistribution.mean).toBe(7.5);
    });

    it('should return 0 for empty scores', () => {
      const snap = cm.getSnapshot();
      expect(snap.riskScoreDistribution.mean).toBe(0);
      expect(snap.riskScoreDistribution.count).toBe(0);
    });
  });

  describe('guardHits', () => {
    it('should record guard hits by type', () => {
      cm.recordGuardHit('duplicate-message-id');
      cm.recordGuardHit('duplicate-message-id');
      cm.recordGuardHit('self-sender-detected');

      const snap = cm.getSnapshot();
      expect(snap.loopPreventionHits['duplicate-message-id']).toBe(2);
      expect(snap.loopPreventionHits['self-sender-detected']).toBe(1);
    });

    it('should track blocked count', () => {
      cm.recordGuardHit('rate-limit');
      cm.recordGuardHit('deduplication');

      const snap = cm.getSnapshot();
      expect(snap.guardPassRate.blocked).toBe(2);
    });

    it('should return empty object when no hits', () => {
      const snap = cm.getSnapshot();
      expect(snap.loopPreventionHits).toEqual({});
    });
  });

  describe('guardPassRate', () => {
    it('should calculate pass rate correctly', () => {
      cm.recordGuardPass();
      cm.recordGuardPass();
      cm.recordGuardPass();
      cm.recordGuardHit('rate-limit');

      const snap = cm.getSnapshot();
      expect(snap.guardPassRate.passed).toBe(3);
      expect(snap.guardPassRate.blocked).toBe(1);
      expect(snap.guardPassRate.rate).toBe(0.75);
    });

    it('should return 0 rate when no emails processed', () => {
      const snap = cm.getSnapshot();
      expect(snap.guardPassRate.rate).toBe(0);
    });

    it('should return 1.0 rate when all pass', () => {
      cm.recordGuardPass();
      cm.recordGuardPass();

      const snap = cm.getSnapshot();
      expect(snap.guardPassRate.rate).toBe(1.0);
    });

    it('should return 0 rate when all blocked', () => {
      cm.recordGuardHit('auto-responder-detected');
      cm.recordGuardHit('missing-sender');

      const snap = cm.getSnapshot();
      expect(snap.guardPassRate.rate).toBe(0);
    });
  });

  describe('webhookLatency', () => {
    it('should record and retrieve webhook latencies', () => {
      cm.recordWebhookLatency(50);
      cm.recordWebhookLatency(100);
      cm.recordWebhookLatency(200);

      const snap = cm.getSnapshot();
      expect(snap.webhookToProcessLatency.count).toBe(3);
      expect(snap.webhookToProcessLatency.p50).toBe(100);
    });

    it('should return 0 for empty latencies', () => {
      const snap = cm.getSnapshot();
      expect(snap.webhookToProcessLatency.p50).toBe(0);
      expect(snap.webhookToProcessLatency.count).toBe(0);
    });
  });

  describe('getPrometheusMetrics', () => {
    it('should generate Prometheus-formatted metrics', () => {
      cm.recordAnalysisDuration(150);
      cm.recordRiskScore(6.0);
      cm.recordGuardHit('rate-limit');
      cm.recordGuardPass();
      cm.recordWebhookLatency(50);

      const prom = cm.getPrometheusMetrics();

      expect(prom).toContain('phishing_agent_analysis_duration_ms{quantile="0.5"} 150');
      expect(prom).toContain('phishing_agent_risk_score{quantile="0.5"} 6');
      expect(prom).toContain('phishing_agent_guard_hits{guard="rate-limit"} 1');
      expect(prom).toContain('phishing_agent_guard_pass_rate 0.5');
      expect(prom).toContain('phishing_agent_webhook_latency_ms{quantile="0.5"} 50');
      expect(prom).toContain('# TYPE');
      expect(prom).toContain('# HELP');
    });

    it('should handle empty metrics without errors', () => {
      const prom = cm.getPrometheusMetrics();
      expect(prom).toContain('phishing_agent_analysis_duration_ms_count 0');
      expect(prom).toContain('phishing_agent_guard_pass_rate 0');
    });
  });

  describe('reset', () => {
    it('should reset all metrics to initial state', () => {
      cm.recordAnalysisDuration(100);
      cm.recordRiskScore(5.0);
      cm.recordGuardHit('rate-limit');
      cm.recordGuardPass();
      cm.recordWebhookLatency(50);

      cm.reset();

      const snap = cm.getSnapshot();
      expect(snap.analysisDurations.count).toBe(0);
      expect(snap.riskScoreDistribution.count).toBe(0);
      expect(snap.loopPreventionHits).toEqual({});
      expect(snap.guardPassRate.passed).toBe(0);
      expect(snap.guardPassRate.blocked).toBe(0);
      expect(snap.webhookToProcessLatency.count).toBe(0);
    });
  });
});
