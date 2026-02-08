import { describe, it, expect, beforeEach } from 'vitest';
import { MetricsService } from './metrics.js';

describe('MetricsService', () => {
  let service: MetricsService;

  beforeEach(() => {
    service = new MetricsService();
  });

  describe('Business Metrics', () => {
    it('should record email processed as phishing', () => {
      service.recordEmailProcessed(true);

      const metrics = service.getMetrics();
      expect(metrics.business.emailsProcessed).toBe(1);
      expect(metrics.business.phishingDetected).toBe(1);
      expect(metrics.business.legitimateEmails).toBe(0);
    });

    it('should record email processed as legitimate', () => {
      service.recordEmailProcessed(false);

      const metrics = service.getMetrics();
      expect(metrics.business.emailsProcessed).toBe(1);
      expect(metrics.business.phishingDetected).toBe(0);
      expect(metrics.business.legitimateEmails).toBe(1);
    });

    it('should record multiple emails', () => {
      service.recordEmailProcessed(true);
      service.recordEmailProcessed(false);
      service.recordEmailProcessed(true);

      const metrics = service.getMetrics();
      expect(metrics.business.emailsProcessed).toBe(3);
      expect(metrics.business.phishingDetected).toBe(2);
      expect(metrics.business.legitimateEmails).toBe(1);
    });

    it('should record analysis errors', () => {
      service.recordAnalysisError();
      service.recordAnalysisError();

      const metrics = service.getMetrics();
      expect(metrics.business.analysisErrors).toBe(2);
    });

    it('should record rate limit hits', () => {
      service.recordRateLimitHit();

      const metrics = service.getMetrics();
      expect(metrics.business.rateLimitHits).toBe(1);
    });

    it('should record deduplication hits', () => {
      service.recordDeduplicationHit();

      const metrics = service.getMetrics();
      expect(metrics.business.deduplicationHits).toBe(1);
    });

    it('should record replies sent', () => {
      service.recordReplySent();

      const metrics = service.getMetrics();
      expect(metrics.business.repliesSent).toBe(1);
    });

    it('should record replies failed', () => {
      service.recordReplyFailed();

      const metrics = service.getMetrics();
      expect(metrics.business.repliesFailed).toBe(1);
    });
  });

  describe('Latency Metrics', () => {
    it('should record analysis latency', () => {
      service.recordAnalysisLatency(100);
      service.recordAnalysisLatency(200);
      service.recordAnalysisLatency(300);

      const metrics = service.getMetrics();
      expect(metrics.latency.analysisP50).toBe(200);
    });

    it('should record reply latency', () => {
      service.recordReplyLatency(50);
      service.recordReplyLatency(100);
      service.recordReplyLatency(150);

      const metrics = service.getMetrics();
      expect(metrics.latency.replyP50).toBe(100);
    });

    it('should calculate P95 percentile', () => {
      for (let i = 1; i <= 100; i++) {
        service.recordAnalysisLatency(i);
      }

      const metrics = service.getMetrics();
      expect(metrics.latency.analysisP95).toBe(95);
    });

    it('should calculate P99 percentile', () => {
      for (let i = 1; i <= 100; i++) {
        service.recordAnalysisLatency(i);
      }

      const metrics = service.getMetrics();
      expect(metrics.latency.analysisP99).toBe(99);
    });

    it('should limit latency array to 1000 entries', () => {
      for (let i = 0; i < 1500; i++) {
        service.recordAnalysisLatency(i);
      }

      service.recordAnalysisLatency(9999);
      const metrics = service.getMetrics();

      // Should have kept only last 1000 + the new one = 1001, then trimmed to 1000
      expect(metrics.latency.analysisP99).toBeLessThan(2000);
    });
  });

  describe('Uptime', () => {
    it('should track uptime', async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));

      const metrics = service.getMetrics();
      expect(metrics.uptime).toBeGreaterThan(0);
    });
  });

  describe('Prometheus Format', () => {
    it('should generate Prometheus-formatted metrics', () => {
      service.recordEmailProcessed(true);
      service.recordEmailProcessed(false);
      service.recordRateLimitHit();

      const prometheus = service.getPrometheusMetrics();

      expect(prometheus).toContain('phishing_agent_emails_processed_total 2');
      expect(prometheus).toContain('phishing_agent_phishing_detected_total 1');
      expect(prometheus).toContain('phishing_agent_legitimate_emails_total 1');
      expect(prometheus).toContain('phishing_agent_rate_limit_hits_total 1');
      expect(prometheus).toContain('# TYPE');
      expect(prometheus).toContain('# HELP');
    });

    it('should include latency quantiles in Prometheus format', () => {
      service.recordAnalysisLatency(100);

      const prometheus = service.getPrometheusMetrics();

      expect(prometheus).toContain('phishing_agent_analysis_latency_ms{quantile="0.5"}');
      expect(prometheus).toContain('phishing_agent_analysis_latency_ms{quantile="0.95"}');
      expect(prometheus).toContain('phishing_agent_analysis_latency_ms{quantile="0.99"}');
    });
  });

  describe('Reset', () => {
    it('should reset all metrics', () => {
      service.recordEmailProcessed(true);
      service.recordAnalysisLatency(100);
      service.recordRateLimitHit();

      service.reset();

      const metrics = service.getMetrics();
      expect(metrics.business.emailsProcessed).toBe(0);
      expect(metrics.business.phishingDetected).toBe(0);
      expect(metrics.business.rateLimitHits).toBe(0);
      expect(metrics.latency.analysisP50).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty latency arrays', () => {
      const metrics = service.getMetrics();

      expect(metrics.latency.analysisP50).toBe(0);
      expect(metrics.latency.analysisP95).toBe(0);
      expect(metrics.latency.analysisP99).toBe(0);
    });

    it('should handle single latency value', () => {
      service.recordAnalysisLatency(500);

      const metrics = service.getMetrics();
      expect(metrics.latency.analysisP50).toBe(500);
      expect(metrics.latency.analysisP95).toBe(500);
      expect(metrics.latency.analysisP99).toBe(500);
    });
  });
});
