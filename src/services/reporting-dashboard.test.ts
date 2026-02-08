import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import type { PhishingAnalysisResult } from '../lib/types.js';

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { ReportingDashboardService } = await import('./reporting-dashboard.js');

describe('ReportingDashboardService', () => {
  let dashboard: InstanceType<typeof ReportingDashboardService>;

  const createMockResult = (overrides: Partial<PhishingAnalysisResult> = {}): PhishingAnalysisResult => ({
    messageId: `msg-${Math.random().toString(36).substring(7)}`,
    isPhishing: false,
    confidence: 0.8,
    riskScore: 3.5,
    severity: 'low',
    indicators: [],
    recommendedActions: [],
    analysisTimestamp: new Date(),
    analysisId: `analysis-${Date.now()}`,
    ...overrides,
  });

  beforeEach(() => {
    dashboard = new ReportingDashboardService();
  });

  describe('Recording Analysis', () => {
    it('should record analysis results', () => {
      const result = createMockResult();
      dashboard.recordAnalysis(result, 'test@example.com');
      expect(dashboard.getResultCount()).toBe(1);
    });

    it('should extract domain from email address', () => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 7 }), 'attacker@malicious.com');
      const report = dashboard.generateReport(1);
      expect(report.topPhishingDomains[0]?.domain).toBe('malicious.com');
    });

    it('should handle email addresses with brackets', () => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 7 }), 'Name <attacker@malicious.com>');
      const report = dashboard.generateReport(1);
      expect(report.topPhishingDomains[0]?.domain).toBe('malicious.com');
    });

    it('should enforce max stored results', () => {
      const smallDashboard = new ReportingDashboardService({ maxStoredResults: 5 });
      for (let i = 0; i < 10; i++) {
        smallDashboard.recordAnalysis(createMockResult(), `test${i}@example.com`);
      }
      expect(smallDashboard.getResultCount()).toBe(5);
    });
  });

  describe('Report Generation', () => {
    beforeEach(() => {
      dashboard.recordAnalysis(
        createMockResult({ isPhishing: true, riskScore: 8, severity: 'critical' }),
        'bad@attacker.com'
      );
      dashboard.recordAnalysis(
        createMockResult({ isPhishing: true, riskScore: 6.5, severity: 'high' }),
        'phish@badguy.com'
      );
      dashboard.recordAnalysis(
        createMockResult({ isPhishing: false, riskScore: 2, severity: 'low' }),
        'legit@goodcompany.com'
      );
      dashboard.recordAnalysis(
        createMockResult({ isPhishing: false, riskScore: 1.5, severity: 'low' }),
        'real@trustedsender.com'
      );
    });

    it('should generate report with summary', () => {
      const report = dashboard.generateReport(7);
      expect(report.summary.totalAnalyzed).toBe(4);
      expect(report.summary.phishingDetected).toBe(2);
      expect(report.summary.legitimateEmails).toBe(2);
      expect(report.summary.detectionRate).toBe(0.5);
    });

    it('should calculate average risk score', () => {
      const report = dashboard.generateReport(7);
      expect(report.summary.avgRiskScore).toBeCloseTo(4.5, 1);
    });

    it('should include severity distribution', () => {
      const report = dashboard.generateReport(7);
      expect(report.severityDistribution.critical).toBe(1);
      expect(report.severityDistribution.high).toBe(1);
      expect(report.severityDistribution.low).toBe(2);
    });

    it('should include period dates', () => {
      const report = dashboard.generateReport(7);
      expect(report.period.start).toBeInstanceOf(Date);
      expect(report.period.end).toBeInstanceOf(Date);
      expect(report.period.end.getTime() - report.period.start.getTime()).toBeCloseTo(7 * 24 * 60 * 60 * 1000, -3);
    });
  });

  describe('Top Phishing Senders', () => {
    beforeEach(() => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 8 }), 'attacker@badguy.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 7 }), 'attacker@badguy.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 9 }), 'hacker@evil.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: false }), 'legit@good.com');
    });

    it('should return top phishing senders sorted by count', () => {
      const topSenders = dashboard.getTopSenders(10);
      expect(topSenders[0].sender).toBe('attacker@badguy.com');
      expect(topSenders[0].phishingEmails).toBe(2);
    });

    it('should calculate average risk score per sender', () => {
      const topSenders = dashboard.getTopSenders(10);
      expect(topSenders[0].avgRiskScore).toBeCloseTo(7.5, 1);
    });

    it('should exclude legitimate senders', () => {
      const topSenders = dashboard.getTopSenders(10);
      expect(topSenders.find((s) => s.sender === 'legit@good.com')).toBeUndefined();
    });

    it('should respect limit parameter', () => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true }), 'a@1.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true }), 'b@2.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true }), 'c@3.com');
      const topSenders = dashboard.getTopSenders(2);
      expect(topSenders.length).toBe(2);
    });
  });

  describe('Top Phishing Domains', () => {
    beforeEach(() => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 8 }), 'user1@badguy.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 7 }), 'user2@badguy.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, riskScore: 9 }), 'hacker@evil.com');
    });

    it('should aggregate by domain', () => {
      const report = dashboard.generateReport(7);
      expect(report.topPhishingDomains[0].domain).toBe('badguy.com');
      expect(report.topPhishingDomains[0].count).toBe(2);
    });

    it('should calculate average risk score per domain', () => {
      const report = dashboard.generateReport(7);
      expect(report.topPhishingDomains[0].avgRiskScore).toBeCloseTo(7.5, 1);
    });
  });

  describe('Daily Metrics', () => {
    it('should return metrics for specific date', () => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true, severity: 'high' }), 'test@example.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: false, severity: 'low' }), 'test2@example.com');
      const metrics = dashboard.getDailyMetrics(new Date());
      expect(metrics.totalAnalyzed).toBe(2);
      expect(metrics.phishingDetected).toBe(1);
      expect(metrics.severityBreakdown.high).toBe(1);
      expect(metrics.severityBreakdown.low).toBe(1);
    });

    it('should return zero metrics for dates with no data', () => {
      const pastDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const metrics = dashboard.getDailyMetrics(pastDate);
      expect(metrics.totalAnalyzed).toBe(0);
      expect(metrics.detectionRate).toBe(0);
    });

    it('should calculate detection rate correctly', () => {
      dashboard.recordAnalysis(createMockResult({ isPhishing: true }), 'a@a.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: true }), 'b@b.com');
      dashboard.recordAnalysis(createMockResult({ isPhishing: false }), 'c@c.com');
      const metrics = dashboard.getDailyMetrics(new Date());
      expect(metrics.detectionRate).toBeCloseTo(0.667, 2);
    });
  });

  describe('Severity Trend', () => {
    it('should return trend data for specified days', () => {
      dashboard.recordAnalysis(createMockResult({ severity: 'critical' }), 'test@example.com');
      const trend = dashboard.getSeverityTrend(7);
      expect(trend.length).toBe(7);
      expect(trend[6].critical).toBe(1);
    });

    it('should include all severity levels in trend', () => {
      const trend = dashboard.getSeverityTrend(3);
      expect(trend[0]).toHaveProperty('critical');
      expect(trend[0]).toHaveProperty('high');
      expect(trend[0]).toHaveProperty('medium');
      expect(trend[0]).toHaveProperty('low');
    });
  });

  describe('Indicator Breakdown', () => {
    it('should aggregate indicators by type', () => {
      dashboard.recordAnalysis(
        createMockResult({
          indicators: [
            {
              type: 'header',
              description: 'SPF fail',
              severity: 'high',
              evidence: 'test',
              confidence: 0.9,
            },
            {
              type: 'content',
              description: 'Phishing URL',
              severity: 'critical',
              evidence: 'test',
              confidence: 0.95,
            },
          ],
        }),
        'test@example.com'
      );
      dashboard.recordAnalysis(
        createMockResult({
          indicators: [
            {
              type: 'header',
              description: 'DKIM fail',
              severity: 'high',
              evidence: 'test',
              confidence: 0.85,
            },
          ],
        }),
        'test2@example.com'
      );

      const report = dashboard.generateReport(7);
      const headerBreakdown = report.indicatorBreakdown.find((i) => i.type === 'header');
      expect(headerBreakdown?.count).toBe(2);
      expect(headerBreakdown?.avgConfidence).toBeCloseTo(0.875, 1);
    });

    it('should sort indicators by count', () => {
      dashboard.recordAnalysis(
        createMockResult({
          indicators: [
            {
              type: 'content',
              description: 'test',
              severity: 'high',
              evidence: 'test',
              confidence: 0.9,
            },
            {
              type: 'content',
              description: 'test',
              severity: 'high',
              evidence: 'test',
              confidence: 0.9,
            },
            {
              type: 'header',
              description: 'test',
              severity: 'high',
              evidence: 'test',
              confidence: 0.9,
            },
          ],
        }),
        'test@example.com'
      );

      const report = dashboard.generateReport(7);
      expect(report.indicatorBreakdown[0].type).toBe('content');
    });
  });

  describe('Reset', () => {
    it('should clear all stored results', () => {
      dashboard.recordAnalysis(createMockResult(), 'test@example.com');
      dashboard.recordAnalysis(createMockResult(), 'test2@example.com');
      expect(dashboard.getResultCount()).toBe(2);
      dashboard.reset();
      expect(dashboard.getResultCount()).toBe(0);
    });
  });

  describe('Empty State', () => {
    it('should handle report generation with no data', () => {
      const report = dashboard.generateReport(7);
      expect(report.summary.totalAnalyzed).toBe(0);
      expect(report.summary.detectionRate).toBe(0);
      expect(report.topPhishingSenders).toHaveLength(0);
      expect(report.topPhishingDomains).toHaveLength(0);
    });

    it('should handle top senders with no data', () => {
      const topSenders = dashboard.getTopSenders(10);
      expect(topSenders).toHaveLength(0);
    });
  });

  describe('Date Formatting', () => {
    it('should format dates correctly in daily metrics', () => {
      dashboard.recordAnalysis(createMockResult(), 'test@example.com');
      const metrics = dashboard.getDailyMetrics(new Date('2024-01-15'));
      expect(metrics.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });
  });
});
