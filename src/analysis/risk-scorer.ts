/**
 * Risk Scorer
 * Aggregates analysis results and calculates risk scores
 * All functions are atomic (max 25 lines)
 */

import { HeaderValidationResult } from './header-validator.js';
import { ContentAnalysisResult } from './content-analyzer.js';
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
    aggregatedScore: number;
  };
}

export class RiskScorer {
  private static readonly PHISHING_THRESHOLD = 5.0;
  private static readonly CRITICAL_THRESHOLD = 8.0;
  private static readonly HIGH_THRESHOLD = 6.0;
  private static readonly MEDIUM_THRESHOLD = 3.0;

  /**
   * Calculate aggregated risk score
   */
  static calculateRisk(
    headerResult: HeaderValidationResult,
    contentResult: ContentAnalysisResult
  ): RiskScoringResult {
    const headerScore = this.calculateHeaderScore(headerResult);
    const contentScore = this.calculateContentScore(contentResult);
    const aggregatedScore = (headerScore * 0.6) + (contentScore * 0.4);
    const riskScore = Math.min(aggregatedScore, 10);
    const isPhishing = riskScore >= this.PHISHING_THRESHOLD;
    const severity = this.determineSeverity(riskScore);

    const indicators = [...headerResult.indicators, ...contentResult.indicators];
    const confidence = this.calculateConfidence(indicators);
    const recommendedActions = this.generateActions(isPhishing, severity, indicators);

    securityLogger.debug('Risk scoring completed', {
      riskScore, isPhishing, severity, headerScore, contentScore, indicatorCount: indicators.length,
    });

    return {
      riskScore, isPhishing, confidence, severity, indicators, recommendedActions,
      analysis: { headerScore, contentScore, aggregatedScore },
    };
  }

  /**
   * Calculate header-based risk score
   */
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

  /**
   * Generate recommended actions
   */
  private static generateActions(
    isPhishing: boolean,
    severity: 'low' | 'medium' | 'high' | 'critical',
    indicators: ThreatIndicator[]
  ): RecommendedAction[] {
    if (!isPhishing) {
      return [{
        priority: 'low',
        action: 'monitor',
        description: 'Email appears legitimate, but continue monitoring',
        automated: true,
        requiresApproval: false,
      }];
    }

    const actions: RecommendedAction[] = [];

    this.addCredentialActions(indicators, actions);
    this.addCriticalActions(severity, actions);
    this.addHighActions(severity, actions);
    this.addMediumActions(severity, actions);
    this.addStandardActions(actions);

    return actions;
  }

  /**
   * Add credential harvesting actions
   */
  private static addCredentialActions(indicators: ThreatIndicator[], actions: RecommendedAction[]): void {
    if (indicators.some(ind => ind.description.includes('Credential'))) {
      actions.push({
        priority: 'urgent',
        action: 'reset_user_credentials',
        description: 'Force password reset if user clicked links',
        automated: false,
        requiresApproval: true,
      });
    }
  }

  /**
   * Add critical severity actions
   */
  private static addCriticalActions(severity: string, actions: RecommendedAction[]): void {
    if (severity !== 'critical') return;

    actions.push({
      priority: 'urgent',
      action: 'quarantine_email',
      description: 'Immediately quarantine and prevent delivery',
      automated: false,
      requiresApproval: true,
    });

    actions.push({
      priority: 'urgent',
      action: 'alert_security_team',
      description: 'Alert security team for immediate investigation',
      automated: true,
      requiresApproval: false,
    });
  }

  /**
   * Add high severity actions
   */
  private static addHighActions(severity: string, actions: RecommendedAction[]): void {
    if (severity !== 'high') return;

    actions.push({
      priority: 'high',
      action: 'quarantine_email',
      description: 'Quarantine email and warn recipient',
      automated: false,
      requiresApproval: true,
    });

    actions.push({
      priority: 'high',
      action: 'notify_recipient',
      description: 'Notify recipient about potential phishing',
      automated: true,
      requiresApproval: false,
    });
  }

  /**
   * Add medium severity actions
   */
  private static addMediumActions(severity: string, actions: RecommendedAction[]): void {
    if (severity !== 'medium') return;

    actions.push({
      priority: 'medium',
      action: 'flag_for_review',
      description: 'Flag email for manual security review',
      automated: true,
      requiresApproval: false,
    });

    actions.push({
      priority: 'medium',
      action: 'user_education',
      description: 'Send security awareness training',
      automated: true,
      requiresApproval: false,
    });
  }

  /**
   * Add standard phishing actions
   */
  private static addStandardActions(actions: RecommendedAction[]): void {
    actions.push({
      priority: 'low',
      action: 'create_incident',
      description: 'Create incident ticket for documentation',
      automated: true,
      requiresApproval: false,
    });
  }

  /**
   * Get human-readable summary
   */
  static getSummary(result: RiskScoringResult): string {
    const emoji = result.isPhishing ? '🚨' : '✅';
    const status = result.isPhishing ? 'PHISHING DETECTED' : 'EMAIL LEGITIMATE';
    const severityEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' }[result.severity];

    return `${emoji} ${status} ${severityEmoji}\n` +
           `Risk Score: ${result.riskScore.toFixed(1)}/10\n` +
           `Confidence: ${(result.confidence * 100).toFixed(0)}%\n` +
           `Severity: ${result.severity.toUpperCase()}\n` +
           `Indicators: ${result.indicators.length}`;
  }
}
