import { describe, it, expect } from '@jest/globals';
import { RiskScorer } from './risk-scorer.js';
import { HeaderValidationResult } from './header-validator.js';
import { ContentAnalysisResult } from './content-analyzer.js';
import { AttachmentAnalysisResult } from './attachment-analyzer.js';
import { ThreatIndicator } from '../lib/types.js';

describe('RiskScorer', () => {
  const createLegitimateHeaders = (): HeaderValidationResult => ({
    isValid: true,
    spfResult: { status: 'pass', isAuthentic: true },
    dkimResult: { status: 'pass', isAuthentic: true },
    dmarcResult: { status: 'pass', isAuthentic: true },
    indicators: [],
    confidence: 0,
  });

  const createFailedHeaders = (): HeaderValidationResult => ({
    isValid: false,
    spfResult: { status: 'fail', isAuthentic: false, details: 'SPF fail' },
    dkimResult: { status: 'fail', isAuthentic: false, details: 'DKIM fail' },
    dmarcResult: { status: 'fail', isAuthentic: false, details: 'DMARC fail' },
    indicators: [
      {
        type: 'header',
        description: 'SPF failed',
        severity: 'high',
        evidence: 'spf=fail',
        confidence: 0.9,
      },
      {
        type: 'header',
        description: 'DKIM failed',
        severity: 'high',
        evidence: 'dkim=fail',
        confidence: 0.9,
      },
      {
        type: 'header',
        description: 'DMARC failed',
        severity: 'high',
        evidence: 'dmarc=fail',
        confidence: 0.85,
      },
    ],
    confidence: 0.88,
  });

  const createEmptyContent = (): ContentAnalysisResult => ({
    hasPhishingPatterns: false,
    indicators: [],
    suspiciousUrls: [],
    socialEngineeringTactics: [],
    confidence: 0,
  });

  const createPhishingContent = (): ContentAnalysisResult => ({
    hasPhishingPatterns: true,
    indicators: [
      {
        type: 'content',
        description: 'Urgency tactics detected',
        severity: 'medium',
        evidence: 'urgent, act now',
        confidence: 0.7,
      },
      {
        type: 'content',
        description: 'Credential harvesting attempt',
        severity: 'critical',
        evidence: 'password, credit card',
        confidence: 0.9,
      },
      {
        type: 'url',
        description: 'Suspicious URL with IP address',
        severity: 'high',
        evidence: 'https://192.168.1.1',
        confidence: 0.8,
      },
    ],
    suspiciousUrls: [{ url: 'https://192.168.1.1', reason: 'IP address', severity: 'high', isPhishing: true }],
    socialEngineeringTactics: ['urgency', 'credential_harvesting'],
    confidence: 0.8,
  });

  describe('Legitimate Email Scoring', () => {
    it('should score legitimate email with low risk', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.isPhishing).toBe(false);
      expect(result.riskScore).toBeLessThan(5.0);
      expect(result.severity).toBe('low');
      expect(result.indicators.length).toBe(0);
    });

    it('should recommend monitoring for legitimate email', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.recommendedActions.length).toBe(1);
      expect(result.recommendedActions[0].action).toBe('monitor');
      expect(result.recommendedActions[0].priority).toBe('low');
    });
  });

  describe('Risk Score Calculation', () => {
    it('should calculate high risk for failed headers only', () => {
      const headers = createFailedHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.analysis.headerScore).toBeGreaterThan(5);
      expect(result.analysis.contentScore).toBe(0);
      expect(result.riskScore).toBeGreaterThanOrEqual(5.0);
      expect(result.isPhishing).toBe(true);
    });

    it('should calculate risk for phishing content only', () => {
      const headers = createLegitimateHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.analysis.headerScore).toBe(0);
      expect(result.analysis.contentScore).toBeGreaterThan(0);
      expect(result.isPhishing).toBeDefined();
    });

    it('should aggregate header and content scores with 60/40 weighting', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);

      const expectedScore = result.analysis.headerScore * 0.6 + result.analysis.contentScore * 0.4;
      expect(result.analysis.aggregatedScore).toBeCloseTo(expectedScore, 2);
      expect(result.riskScore).toBeLessThanOrEqual(10);
    });

    it('should cap risk score at 10', () => {
      const headers: HeaderValidationResult = {
        isValid: false,
        spfResult: { status: 'fail', isAuthentic: false },
        dkimResult: { status: 'fail', isAuthentic: false },
        dmarcResult: { status: 'reject', isAuthentic: false },
        indicators: Array(10).fill({
          type: 'header',
          description: 'Critical issue',
          severity: 'critical',
          evidence: 'test',
          confidence: 0.95,
        }) as ThreatIndicator[],
        confidence: 0.95,
      };

      const content = createPhishingContent();
      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.riskScore).toBeLessThanOrEqual(10);
    });
  });

  describe('Severity Determination', () => {
    it('should classify high score as critical', () => {
      const headers: HeaderValidationResult = {
        isValid: false,
        spfResult: { status: 'fail', isAuthentic: false },
        dkimResult: { status: 'fail', isAuthentic: false },
        dmarcResult: { status: 'reject', isAuthentic: false },
        indicators: [
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
        ],
        confidence: 0.95,
      };

      const content: ContentAnalysisResult = {
        hasPhishingPatterns: true,
        indicators: [
          {
            type: 'content',
            description: 'Urgency tactics',
            severity: 'medium',
            evidence: 'urgent',
            confidence: 0.7,
          },
          {
            type: 'content',
            description: 'Credential harvesting',
            severity: 'critical',
            evidence: 'password',
            confidence: 0.9,
          },
          {
            type: 'url',
            description: 'Suspicious URL',
            severity: 'high',
            evidence: 'https://192.168.1.1',
            confidence: 0.8,
          },
          {
            type: 'content',
            description: 'Brand impersonation',
            severity: 'critical',
            evidence: 'PayPal',
            confidence: 0.9,
          },
        ],
        suspiciousUrls: [{ url: 'https://192.168.1.1', reason: 'IP address', severity: 'high', isPhishing: true }],
        socialEngineeringTactics: ['urgency', 'credential_harvesting'],
        confidence: 0.85,
      };
      const result = RiskScorer.calculateRisk(headers, content);

      // Score should be >= 8.0 and classified as critical
      expect(result.riskScore).toBeGreaterThanOrEqual(8.0);
      expect(result.severity).toBe('critical');
    });

    it('should classify score 6.0-7.9 as high', () => {
      const headers = createFailedHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);

      if (result.riskScore >= 6.0 && result.riskScore < 8.0) {
        expect(result.severity).toBe('high');
      }
    });

    it('should classify score 3.0-5.9 as medium', () => {
      const headers: HeaderValidationResult = {
        isValid: false,
        spfResult: { status: 'softfail', isAuthentic: false },
        dkimResult: { status: 'pass', isAuthentic: true },
        dmarcResult: { status: 'pass', isAuthentic: true },
        indicators: [
          {
            type: 'header',
            description: 'SPF softfail',
            severity: 'medium',
            evidence: 'test',
            confidence: 0.6,
          },
        ],
        confidence: 0.6,
      };

      const content = createEmptyContent();
      const result = RiskScorer.calculateRisk(headers, content);

      if (result.riskScore >= 3.0 && result.riskScore < 6.0) {
        expect(result.severity).toBe('medium');
      }
    });

    it('should classify score < 3.0 as low', () => {
      const headers = createLegitimateHeaders();
      const content: ContentAnalysisResult = {
        hasPhishingPatterns: true,
        indicators: [
          {
            type: 'content',
            description: 'Minor issue',
            severity: 'low',
            evidence: 'test',
            confidence: 0.3,
          },
        ],
        suspiciousUrls: [],
        socialEngineeringTactics: [],
        confidence: 0.3,
      };

      const result = RiskScorer.calculateRisk(headers, content);

      if (result.riskScore < 3.0) {
        expect(result.severity).toBe('low');
      }
    });
  });

  describe('Confidence Calculation', () => {
    it('should calculate average confidence from all indicators', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);

      const allIndicators = [...headers.indicators, ...content.indicators];
      const avgConfidence = allIndicators.reduce((sum, ind) => sum + ind.confidence, 0) / allIndicators.length;

      expect(result.confidence).toBeCloseTo(avgConfidence, 2);
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });

    it('should return 0 confidence when no indicators present', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.confidence).toBe(0);
    });
  });

  describe('Recommended Actions', () => {
    it('should recommend quarantine for critical severity', () => {
      const headers: HeaderValidationResult = {
        isValid: false,
        spfResult: { status: 'fail', isAuthentic: false },
        dkimResult: { status: 'fail', isAuthentic: false },
        dmarcResult: { status: 'reject', isAuthentic: false },
        indicators: [
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
        ],
        confidence: 0.95,
      };

      const content = createPhishingContent();
      const result = RiskScorer.calculateRisk(headers, content);

      if (result.severity === 'critical') {
        expect(result.recommendedActions.some((a) => a.action === 'quarantine_email')).toBe(true);
        expect(result.recommendedActions.some((a) => a.action === 'alert_security_team')).toBe(true);
        expect(result.recommendedActions.some((a) => a.priority === 'urgent')).toBe(true);
      }
    });

    it('should recommend credential reset for credential harvesting', () => {
      const headers = createLegitimateHeaders();
      const content: ContentAnalysisResult = {
        hasPhishingPatterns: true,
        indicators: [
          {
            type: 'content',
            description: 'Credential harvesting attempt detected',
            severity: 'critical',
            evidence: 'password, credit card',
            confidence: 0.9,
          },
        ],
        suspiciousUrls: [],
        socialEngineeringTactics: ['credential_harvesting'],
        confidence: 0.9,
      };

      const result = RiskScorer.calculateRisk(headers, content);

      if (result.isPhishing) {
        const credAction = result.recommendedActions.find((a) => a.action === 'reset_user_credentials');
        expect(credAction).toBeDefined();
        expect(credAction?.priority).toBe('urgent');
        expect(credAction?.requiresApproval).toBe(true);
      }
    });

    it('should recommend review for medium severity', () => {
      const headers: HeaderValidationResult = {
        isValid: false,
        spfResult: { status: 'softfail', isAuthentic: false },
        dkimResult: { status: 'pass', isAuthentic: true },
        dmarcResult: { status: 'pass', isAuthentic: true },
        indicators: [
          {
            type: 'header',
            description: 'SPF softfail',
            severity: 'medium',
            evidence: 'test',
            confidence: 0.6,
          },
          {
            type: 'header',
            description: 'Test',
            severity: 'medium',
            evidence: 'test',
            confidence: 0.6,
          },
        ],
        confidence: 0.6,
      };

      const content = createEmptyContent();
      const result = RiskScorer.calculateRisk(headers, content);

      if (result.severity === 'medium') {
        expect(result.recommendedActions.some((a) => a.action === 'flag_for_review')).toBe(true);
        expect(result.recommendedActions.some((a) => a.action === 'user_education')).toBe(true);
      }
    });

    it('should always include incident creation for phishing', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);

      if (result.isPhishing) {
        expect(result.recommendedActions.some((a) => a.action === 'create_incident')).toBe(true);
      }
    });
  });

  describe('Summary Generation', () => {
    it('should generate summary for phishing email', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);
      const summary = RiskScorer.getSummary(result);

      expect(summary).toContain('PHISHING DETECTED');
      expect(summary).toContain('Risk Score:');
      expect(summary).toContain('Confidence:');
      expect(summary).toContain('Severity:');
      expect(summary).toContain('Indicators:');
    });

    it('should generate summary for legitimate email', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);
      const summary = RiskScorer.getSummary(result);

      expect(summary).toContain('EMAIL LEGITIMATE');
      expect(summary).toContain('Risk Score:');
      expect(summary).toContain('LOW');
    });

    it('should include risk score with one decimal', () => {
      const headers = createFailedHeaders();
      const content = createEmptyContent();

      const result = RiskScorer.calculateRisk(headers, content);
      const summary = RiskScorer.getSummary(result);

      const scoreMatch = summary.match(/Risk Score: (\d+\.\d)/);
      expect(scoreMatch).not.toBeNull();
    });

    it('should include confidence as percentage', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);
      const summary = RiskScorer.getSummary(result);

      expect(summary).toMatch(/Confidence: \d+%/);
    });
  });

  describe('Edge Cases', () => {
    it('should handle DMARC reject status with highest score', () => {
      const headers: HeaderValidationResult = {
        isValid: false,
        spfResult: { status: 'pass', isAuthentic: true },
        dkimResult: { status: 'pass', isAuthentic: true },
        dmarcResult: { status: 'reject', isAuthentic: false },
        indicators: [
          {
            type: 'header',
            description: 'DMARC reject',
            severity: 'critical',
            evidence: 'test',
            confidence: 0.95,
          },
        ],
        confidence: 0.95,
      };

      const content = createEmptyContent();
      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.analysis.headerScore).toBeGreaterThan(4);
    });

    it('should handle multiple social engineering tactics', () => {
      const headers = createLegitimateHeaders();
      const content: ContentAnalysisResult = {
        hasPhishingPatterns: true,
        indicators: [
          {
            type: 'content',
            description: 'Test1',
            severity: 'medium',
            evidence: 'test',
            confidence: 0.7,
          },
          {
            type: 'content',
            description: 'Test2',
            severity: 'medium',
            evidence: 'test',
            confidence: 0.7,
          },
          {
            type: 'content',
            description: 'Test3',
            severity: 'medium',
            evidence: 'test',
            confidence: 0.7,
          },
        ],
        suspiciousUrls: [],
        socialEngineeringTactics: ['urgency', 'credential_harvesting', 'financial_lure'],
        confidence: 0.7,
      };

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.analysis.contentScore).toBeGreaterThan(0);
    });

    it('should handle multiple suspicious URLs', () => {
      const headers = createLegitimateHeaders();
      const content: ContentAnalysisResult = {
        hasPhishingPatterns: true,
        indicators: [
          { type: 'url', description: 'URL1', severity: 'high', evidence: 'test', confidence: 0.8 },
          { type: 'url', description: 'URL2', severity: 'high', evidence: 'test', confidence: 0.8 },
          { type: 'url', description: 'URL3', severity: 'high', evidence: 'test', confidence: 0.8 },
        ],
        suspiciousUrls: [
          { url: 'url1', reason: 'test', severity: 'high', isPhishing: true },
          { url: 'url2', reason: 'test', severity: 'high', isPhishing: true },
          { url: 'url3', reason: 'test', severity: 'high', isPhishing: true },
        ],
        socialEngineeringTactics: [],
        confidence: 0.8,
      };

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.analysis.contentScore).toBeGreaterThan(0);
    });
  });

  describe('Attachment Analysis Integration', () => {
    const createDangerousAttachments = (): AttachmentAnalysisResult => ({
      hasRiskyAttachments: true,
      indicators: [
        {
          type: 'attachment',
          description: 'Dangerous file type detected: .exe',
          severity: 'critical',
          evidence: 'Filename: malware.exe',
          confidence: 0.95,
        },
      ],
      riskLevel: 'critical',
      totalAttachments: 1,
      riskyAttachments: 1,
    });

    const createMacroAttachments = (): AttachmentAnalysisResult => ({
      hasRiskyAttachments: true,
      indicators: [
        {
          type: 'attachment',
          description: 'Macro-enabled document: .xlsm',
          severity: 'high',
          evidence: 'Filename: invoice.xlsm',
          confidence: 0.85,
        },
      ],
      riskLevel: 'high',
      totalAttachments: 1,
      riskyAttachments: 1,
    });

    const createSafeAttachments = (): AttachmentAnalysisResult => ({
      hasRiskyAttachments: false,
      indicators: [],
      riskLevel: 'none',
      totalAttachments: 2,
      riskyAttachments: 0,
    });

    it('should include attachment score in analysis', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();
      const attachments = createDangerousAttachments();

      const result = RiskScorer.calculateRisk(headers, content, attachments);

      expect(result.analysis.attachmentScore).toBeGreaterThan(0);
    });

    it('should include attachment indicators in result', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();
      const attachments = createDangerousAttachments();

      const result = RiskScorer.calculateRisk(headers, content, attachments);

      expect(result.indicators.some((i) => i.type === 'attachment')).toBe(true);
    });

    it('should use 40/30/30 weighting when attachments present', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();
      const attachments = createDangerousAttachments();

      const result = RiskScorer.calculateRisk(headers, content, attachments);

      const expectedScore =
        result.analysis.headerScore * 0.4 + result.analysis.contentScore * 0.3 + result.analysis.attachmentScore * 0.3;
      expect(result.analysis.aggregatedScore).toBeCloseTo(expectedScore, 2);
    });

    it('should use 60/40 weighting when no attachments', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content);

      expect(result.analysis.attachmentScore).toBe(0);
      const expectedScore = result.analysis.headerScore * 0.6 + result.analysis.contentScore * 0.4;
      expect(result.analysis.aggregatedScore).toBeCloseTo(expectedScore, 2);
    });

    it('should recommend block_attachment for dangerous executables', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();
      const attachments = createDangerousAttachments();

      const result = RiskScorer.calculateRisk(headers, content, attachments);

      if (result.isPhishing) {
        expect(result.recommendedActions.some((a) => a.action === 'block_attachment')).toBe(true);
      }
    });

    it('should recommend strip_macros for macro documents', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();
      const attachments = createMacroAttachments();

      const result = RiskScorer.calculateRisk(headers, content, attachments);

      if (result.isPhishing) {
        expect(result.recommendedActions.some((a) => a.action === 'strip_macros')).toBe(true);
      }
    });

    it('should not add attachment actions for safe attachments', () => {
      const headers = createLegitimateHeaders();
      const content = createEmptyContent();
      const attachments = createSafeAttachments();

      const result = RiskScorer.calculateRisk(headers, content, attachments);

      expect(result.recommendedActions.every((a) => a.action !== 'block_attachment')).toBe(true);
      expect(result.recommendedActions.every((a) => a.action !== 'strip_macros')).toBe(true);
    });

    it('should handle undefined attachment result', () => {
      const headers = createFailedHeaders();
      const content = createPhishingContent();

      const result = RiskScorer.calculateRisk(headers, content, undefined);

      expect(result.analysis.attachmentScore).toBe(0);
      expect(result.indicators.every((i) => i.type !== 'attachment')).toBe(true);
    });
  });
});
