/** Risk Scorer - Aggregates analysis results and calculates risk scores */
import { HeaderValidationResult } from './header-validator.js';
import { ContentAnalysisResult } from './content-analyzer.js';
import { AttachmentAnalysisResult } from './attachment-analyzer.js';
import { ThreatIndicator, RecommendedAction } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';

export interface RiskScoringResult {
  riskScore: number; // 0-10
  isPhishing: boolean;
  confidence: number; // 0-1
  severity: 'low' | 'medium' | 'high' | 'critical';
  indicators: ThreatIndicator[];
  recommendedActions: RecommendedAction[];
  analysis: {
    headerScore: number;
    contentScore: number;
    attachmentScore: number;
    aggregatedScore: number;
  };
}

export class RiskScorer {
  private static readonly PHISHING_THRESHOLD = 5.0;
  private static readonly CRITICAL_THRESHOLD = 8.0;
  private static readonly HIGH_THRESHOLD = 6.0;
  private static readonly MEDIUM_THRESHOLD = 3.0;

  static calculateRisk(
    headerResult: HeaderValidationResult,
    contentResult: ContentAnalysisResult,
    attachmentResult?: AttachmentAnalysisResult
  ): RiskScoringResult {
    const headerScore = this.calculateHeaderScore(headerResult);
    const contentScore = this.calculateContentScore(contentResult);
    const attachmentScore = attachmentResult ? this.calculateAttachmentScore(attachmentResult) : 0;

    const aggregatedScore = this.aggregateScores(headerScore, contentScore, attachmentScore);
    const riskScore = Math.min(aggregatedScore, 10);
    const isPhishing = riskScore >= this.PHISHING_THRESHOLD;
    const severity = this.determineSeverity(riskScore);

    const indicators = this.collectIndicators(headerResult, contentResult, attachmentResult);
    const confidence = this.calculateConfidence(indicators);
    const recommendedActions = this.generateActions(isPhishing, severity, indicators);

    securityLogger.debug('Risk scoring completed', {
      riskScore,
      isPhishing,
      severity,
      headerScore,
      contentScore,
      attachmentScore,
      indicatorCount: indicators.length,
    });

    return {
      riskScore,
      isPhishing,
      confidence,
      severity,
      indicators,
      recommendedActions,
      analysis: { headerScore, contentScore, attachmentScore, aggregatedScore },
    };
  }

  private static aggregateScores(header: number, content: number, attachment: number): number {
    if (attachment > 0) {
      return header * 0.4 + content * 0.3 + attachment * 0.3;
    }
    return header * 0.6 + content * 0.4;
  }

  private static collectIndicators(
    headerResult: HeaderValidationResult,
    contentResult: ContentAnalysisResult,
    attachmentResult?: AttachmentAnalysisResult
  ): ThreatIndicator[] {
    const indicators = [...headerResult.indicators, ...contentResult.indicators];
    if (attachmentResult) {
      indicators.push(...attachmentResult.indicators);
    }
    return indicators;
  }

  private static calculateAttachmentScore(result: AttachmentAnalysisResult): number {
    if (!result.hasRiskyAttachments) return 0;
    return this.scoreIndicators(result.indicators);
  }

  private static calculateHeaderScore(result: HeaderValidationResult): number {
    let score = 0;

    if (!result.spfResult.isAuthentic) {
      score += result.spfResult.status === 'fail' ? 3 : 1.5;
    }
    if (!result.dkimResult.isAuthentic) {
      score += result.dkimResult.status === 'fail' ? 3 : 1.5;
    }
    if (!result.dmarcResult.isAuthentic) {
      score += this.getDmarcScore(result.dmarcResult.status);
    }

    score += this.scoreIndicators(result.indicators);

    return Math.min(score, 10);
  }

  /**
   * Get DMARC failure score
   */
  private static getDmarcScore(status: string): number {
    if (status === 'reject') return 4;
    if (status === 'fail') return 3;
    return 1.5;
  }

  /**
   * Score indicators by severity
   */
  private static scoreIndicators(indicators: ThreatIndicator[]): number {
    let score = 0;
    for (const ind of indicators) {
      if (ind.severity === 'critical') score += 2.5;
      else if (ind.severity === 'high') score += 1.5;
      else if (ind.severity === 'medium') score += 0.75;
      else score += 0.25;
    }
    return score;
  }

  /**
   * Calculate content-based risk score
   */
  private static calculateContentScore(result: ContentAnalysisResult): number {
    if (!result.hasPhishingPatterns) return 0;

    let score = this.scoreIndicators(result.indicators);

    if (result.socialEngineeringTactics.length > 2) score += 1;
    if (result.suspiciousUrls.length > 2) score += 1;

    return Math.min(score, 10);
  }

  /**
   * Determine severity level
   */
  private static determineSeverity(riskScore: number): 'low' | 'medium' | 'high' | 'critical' {
    if (riskScore >= this.CRITICAL_THRESHOLD) return 'critical';
    if (riskScore >= this.HIGH_THRESHOLD) return 'high';
    if (riskScore >= this.MEDIUM_THRESHOLD) return 'medium';
    return 'low';
  }

  /**
   * Calculate average confidence
   */
  private static calculateConfidence(indicators: ThreatIndicator[]): number {
    if (indicators.length === 0) return 0;
    return indicators.reduce((sum, ind) => sum + ind.confidence, 0) / indicators.length;
  }

  private static action(
    priority: 'low' | 'medium' | 'high' | 'urgent',
    action: string,
    description: string,
    automated: boolean,
    requiresApproval: boolean
  ): RecommendedAction {
    return { priority, action, description, automated, requiresApproval };
  }

  private static generateActions(
    isPhishing: boolean,
    severity: 'low' | 'medium' | 'high' | 'critical',
    indicators: ThreatIndicator[]
  ): RecommendedAction[] {
    if (!isPhishing) return [this.action('low', 'monitor', 'Email appears legitimate', true, false)];

    const actions = this.getIndicatorActions(indicators);
    actions.push(...this.getSeverityActions(severity));
    actions.push(this.action('low', 'create_incident', 'Create incident ticket', true, false));
    return actions;
  }

  private static getIndicatorActions(indicators: ThreatIndicator[]): RecommendedAction[] {
    const actions: RecommendedAction[] = [];
    if (indicators.some((i) => i.description.includes('Credential')))
      actions.push(this.action('urgent', 'reset_user_credentials', 'Force password reset', false, true));
    if (indicators.some((i) => i.type === 'attachment' && i.severity === 'critical'))
      actions.push(this.action('urgent', 'block_attachment', 'Block dangerous attachment', true, false));
    if (indicators.some((i) => i.type === 'attachment' && i.description.includes('Macro')))
      actions.push(this.action('high', 'strip_macros', 'Remove macros from document', false, true));
    return actions;
  }

  private static getSeverityActions(severity: 'low' | 'medium' | 'high' | 'critical'): RecommendedAction[] {
    if (severity === 'critical') {
      return [
        this.action('urgent', 'quarantine_email', 'Quarantine and prevent delivery', false, true),
        this.action('urgent', 'alert_security_team', 'Alert security team', true, false),
      ];
    }
    if (severity === 'high') {
      return [
        this.action('high', 'quarantine_email', 'Quarantine and warn recipient', false, true),
        this.action('high', 'notify_recipient', 'Notify recipient', true, false),
      ];
    }
    if (severity === 'medium') {
      return [
        this.action('medium', 'flag_for_review', 'Flag for manual review', true, false),
        this.action('medium', 'user_education', 'Send security training', true, false),
      ];
    }
    return [];
  }

  static getSummary(result: RiskScoringResult): string {
    const emoji = result.isPhishing ? '🚨' : '✅';
    const status = result.isPhishing ? 'PHISHING DETECTED' : 'EMAIL LEGITIMATE';
    const sev = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' }[result.severity];
    return `${emoji} ${status} ${sev}\nRisk Score: ${result.riskScore.toFixed(1)}/10\nConfidence: ${(result.confidence * 100).toFixed(0)}%\nSeverity: ${result.severity.toUpperCase()}\nIndicators: ${result.indicators.length}`;
  }
}
