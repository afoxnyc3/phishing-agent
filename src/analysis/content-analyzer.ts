/**
 * Content Analyzer
 * Detects phishing patterns in email body content
 * Orchestrates URL, social engineering, and brand detection modules
 * All functions are atomic (max 25 lines)
 */

import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { UrlAnalyzer, SuspiciousUrl } from './url-analyzer.js';
import { SocialEngineeringDetector } from './social-engineering-detector.js';
import { BrandDetector } from './brand-detector.js';

// Re-export for backward compatibility
export { SuspiciousUrl } from './url-analyzer.js';

export interface ContentAnalysisResult {
  hasPhishingPatterns: boolean;
  indicators: ThreatIndicator[];
  suspiciousUrls: SuspiciousUrl[];
  socialEngineeringTactics: string[];
  confidence: number;
}

export class ContentAnalyzer {
  /**
   * Analyze email body content with optional sender domain
   */
  static analyze(body: string, senderDomain?: string): ContentAnalysisResult {
    const indicators: ThreatIndicator[] = [];
    const suspiciousUrls: SuspiciousUrl[] = [];
    const tactics: string[] = [];

    const trimmedBody = (body || '').trim();
    if (trimmedBody.length > 0) {
      this.analyzeUrgency(trimmedBody, indicators, tactics);
      this.analyzeCredentialRequests(trimmedBody, indicators, tactics);
      this.analyzeFinancialLures(trimmedBody, indicators, tactics);
      this.analyzeUrls(trimmedBody, indicators, suspiciousUrls);
      this.analyzeMismatchedLinks(trimmedBody, indicators, tactics);

      if (senderDomain) {
        this.analyzeBrandImpersonation(trimmedBody, senderDomain, indicators);
      }
    }

    if (senderDomain) {
      this.analyzeTyposquatting(senderDomain, indicators);
    }

    const confidence = this.calculateConfidence(indicators);
    const hasPhishingPatterns = indicators.length > 0;

    securityLogger.debug('Content analysis completed', {
      hasPhishingPatterns,
      indicatorCount: indicators.length,
      suspiciousUrlCount: suspiciousUrls.length,
      tactics,
    });

    return { hasPhishingPatterns, indicators, suspiciousUrls, socialEngineeringTactics: tactics, confidence };
  }

  /**
   * Analyze for urgency tactics
   */
  private static analyzeUrgency(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const indicator = SocialEngineeringDetector.detectUrgencyTactics(body);
    if (indicator) {
      indicators.push(indicator);
      tactics.push('urgency');
    }
  }

  /**
   * Analyze for credential requests
   */
  private static analyzeCredentialRequests(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const indicator = SocialEngineeringDetector.detectCredentialRequests(body);
    if (indicator) {
      indicators.push(indicator);
      tactics.push('credential_harvesting');
    }
  }

  /**
   * Analyze for financial lures
   */
  private static analyzeFinancialLures(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const indicator = SocialEngineeringDetector.detectFinancialLures(body);
    if (indicator) {
      indicators.push(indicator);
      tactics.push('financial_lure');
    }
  }

  /**
   * Analyze URLs in body
   */
  private static analyzeUrls(body: string, indicators: ThreatIndicator[], suspiciousUrls: SuspiciousUrl[]): void {
    const result = UrlAnalyzer.analyzeUrls(body);
    indicators.push(...result.indicators);
    suspiciousUrls.push(...result.suspiciousUrls);
  }

  /**
   * Analyze for mismatched links
   */
  private static analyzeMismatchedLinks(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const mismatched = UrlAnalyzer.detectMismatchedLinks(body);
    if (mismatched.length > 0) {
      indicators.push({
        type: 'content',
        description: 'Mismatched link text and URL detected',
        severity: 'high',
        evidence: `Found ${mismatched.length} mismatched links`,
        confidence: 0.85,
      });
      tactics.push('link_obfuscation');
    }
  }

  /**
   * Analyze brand impersonation
   */
  private static analyzeBrandImpersonation(body: string, fromDomain: string, indicators: ThreatIndicator[]): void {
    const indicator = BrandDetector.detectBrandImpersonation(body, fromDomain);
    if (indicator) {
      indicators.push(indicator);
    }
  }

  /**
   * Analyze typosquatting
   */
  private static analyzeTyposquatting(fromDomain: string, indicators: ThreatIndicator[]): void {
    const indicator = BrandDetector.detectTyposquatting(fromDomain);
    if (indicator) {
      indicators.push(indicator);
    }
  }

  /**
   * Calculate average confidence
   */
  private static calculateConfidence(indicators: ThreatIndicator[]): number {
    if (indicators.length === 0) return 0;
    return indicators.reduce((sum, ind) => sum + ind.confidence, 0) / indicators.length;
  }

  /**
   * Detect brand impersonation (public API for backward compatibility)
   */
  static detectBrandImpersonation(body: string, fromDomain: string): ThreatIndicator | null {
    return BrandDetector.detectBrandImpersonation(body, fromDomain);
  }

  /**
   * Detect typosquatting (public API for backward compatibility)
   */
  static detectTyposquatting(fromDomain: string): ThreatIndicator | null {
    return BrandDetector.detectTyposquatting(fromDomain);
  }
}
