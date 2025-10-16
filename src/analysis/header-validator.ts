/**
 * Header Validator
 * Validates email authentication headers (SPF, DKIM, DMARC)
 * All functions are atomic (max 25 lines)
 */

import { EmailHeaders, ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';

export interface HeaderValidationResult {
  isValid: boolean;
  spfResult: SPFResult;
  dkimResult: DKIMResult;
  dmarcResult: DMARCResult;
  indicators: ThreatIndicator[];
  confidence: number;
}

export interface SPFResult {
  status: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  details?: string;
  isAuthentic: boolean;
}

export interface DKIMResult {
  status: 'pass' | 'fail' | 'none' | 'neutral' | 'temperror' | 'permerror';
  details?: string;
  isAuthentic: boolean;
}

export interface DMARCResult {
  status: 'pass' | 'fail' | 'none' | 'quarantine' | 'reject';
  policy?: string;
  details?: string;
  isAuthentic: boolean;
}

export class HeaderValidator {
  /**
   * Validate email authentication headers
   */
  static validate(headers: EmailHeaders): HeaderValidationResult {
    const spfResult = this.validateSPF(headers);
    const dkimResult = this.validateDKIM(headers);
    const dmarcResult = this.validateDMARC(headers);

    const indicators: ThreatIndicator[] = [];
    this.collectSpfIndicators(spfResult, indicators);
    this.collectDkimIndicators(dkimResult, indicators);
    this.collectDmarcIndicators(dmarcResult, indicators);

    const avgConfidence = this.calculateAverageConfidence(indicators);
    const isValid = spfResult.isAuthentic && dkimResult.isAuthentic && dmarcResult.isAuthentic;

    securityLogger.debug('Header validation completed', {
      isValid,
      spf: spfResult.status,
      dkim: dkimResult.status,
      dmarc: dmarcResult.status,
      indicatorCount: indicators.length,
    });

    return { isValid, spfResult, dkimResult, dmarcResult, indicators, confidence: avgConfidence };
  }

  /**
   * Collect SPF failure indicators
   */
  private static collectSpfIndicators(result: SPFResult, indicators: ThreatIndicator[]): void {
    if (!result.isAuthentic) {
      indicators.push({
        type: 'header',
        description: `SPF authentication failed: ${result.status}`,
        severity: result.status === 'fail' ? 'high' : 'medium',
        evidence: result.details || `SPF status: ${result.status}`,
        confidence: result.status === 'fail' ? 0.9 : 0.6,
      });
    }
  }

  /**
   * Collect DKIM failure indicators
   */
  private static collectDkimIndicators(result: DKIMResult, indicators: ThreatIndicator[]): void {
    if (!result.isAuthentic) {
      indicators.push({
        type: 'header',
        description: `DKIM signature validation failed: ${result.status}`,
        severity: result.status === 'fail' ? 'high' : 'medium',
        evidence: result.details || `DKIM status: ${result.status}`,
        confidence: result.status === 'fail' ? 0.9 : 0.5,
      });
    }
  }

  /**
   * Collect DMARC failure indicators
   */
  private static collectDmarcIndicators(result: DMARCResult, indicators: ThreatIndicator[]): void {
    if (!result.isAuthentic) {
      const severity = result.status === 'reject' ? 'critical' : result.status === 'fail' ? 'high' : 'medium';
      indicators.push({
        type: 'header',
        description: `DMARC policy validation failed: ${result.status}`,
        severity,
        evidence: result.details || `DMARC status: ${result.status}`,
        confidence: result.status === 'fail' || result.status === 'reject' ? 0.85 : 0.5,
      });
    }
  }

  /**
   * Calculate average confidence from indicators
   */
  private static calculateAverageConfidence(indicators: ThreatIndicator[]): number {
    if (indicators.length === 0) return 0;
    return indicators.reduce((sum, ind) => sum + ind.confidence, 0) / indicators.length;
  }

  /**
   * Validate SPF (Sender Policy Framework)
   */
  private static validateSPF(headers: EmailHeaders): SPFResult {
    const spfHeader = headers['received-spf'] || headers['authentication-results'];

    if (!spfHeader) {
      return { status: 'none', details: 'No SPF header found', isAuthentic: false };
    }

    const status = this.parseSpfStatus(spfHeader);
    return {
      status,
      details: spfHeader,
      isAuthentic: status === 'pass',
    };
  }

  /**
   * Parse SPF status from header
   */
  private static parseSpfStatus(header: string): SPFResult['status'] {
    const lower = header.toLowerCase();

    if (lower.includes('spf=pass') || lower.startsWith('pass')) return 'pass';
    if (lower.includes('spf=fail') || lower.startsWith('fail')) return 'fail';
    if (lower.includes('spf=softfail') || lower.startsWith('softfail')) return 'softfail';
    if (lower.includes('spf=neutral')) return 'neutral';
    if (lower.includes('spf=temperror')) return 'temperror';
    if (lower.includes('spf=permerror')) return 'permerror';

    return 'none';
  }

  /**
   * Validate DKIM (DomainKeys Identified Mail)
   */
  private static validateDKIM(headers: EmailHeaders): DKIMResult {
    const authResults = headers['authentication-results'];

    if (!authResults) {
      return { status: 'none', details: 'No DKIM authentication results found', isAuthentic: false };
    }

    const status = this.parseDkimStatus(authResults);
    return {
      status,
      details: authResults,
      isAuthentic: status === 'pass',
    };
  }

  /**
   * Parse DKIM status from authentication results
   */
  private static parseDkimStatus(header: string): DKIMResult['status'] {
    const lower = header.toLowerCase();

    if (lower.includes('dkim=pass')) return 'pass';
    if (lower.includes('dkim=fail')) return 'fail';
    if (lower.includes('dkim=neutral')) return 'neutral';
    if (lower.includes('dkim=temperror')) return 'temperror';
    if (lower.includes('dkim=permerror')) return 'permerror';

    return 'none';
  }

  /**
   * Validate DMARC
   */
  private static validateDMARC(headers: EmailHeaders): DMARCResult {
    const authResults = headers['authentication-results'];
    const dmarcHeader = headers['dmarc-results'];
    const checkHeader = authResults || dmarcHeader;

    if (!checkHeader) {
      return { status: 'none', details: 'No DMARC results found', isAuthentic: false };
    }

    const status = this.parseDmarcStatus(checkHeader);
    return {
      status,
      details: checkHeader,
      isAuthentic: status === 'pass',
    };
  }

  /**
   * Parse DMARC status from header
   */
  private static parseDmarcStatus(header: string): DMARCResult['status'] {
    const lower = header.toLowerCase();

    if (lower.includes('dmarc=pass')) return 'pass';
    if (lower.includes('dmarc=fail')) return 'fail';
    if (lower.includes('dmarc=quarantine')) return 'quarantine';
    if (lower.includes('dmarc=reject')) return 'reject';

    return 'none';
  }

  /**
   * Check for domain spoofing
   */
  static checkDomainSpoofing(headers: EmailHeaders): ThreatIndicator | null {
    const from = headers.from;
    const authResults = headers['authentication-results'];

    if (!from || !authResults) return null;

    const fromDomain = this.extractDomainFromHeader(from);
    const authDomain = this.extractAuthDomain(authResults);

    if (fromDomain && authDomain && !this.domainsMatch(fromDomain, authDomain)) {
      return {
        type: 'header',
        description: 'Sender domain mismatch detected - possible spoofing',
        severity: 'critical',
        evidence: `From domain: ${fromDomain}, Auth domain: ${authDomain}`,
        confidence: 0.95,
      };
    }

    return null;
  }

  /**
   * Extract domain from email header
   */
  private static extractDomainFromHeader(from: string): string | null {
    const match = from.match(/@([^>\s]+)/);
    return match ? match[1].toLowerCase() : null;
  }

  /**
   * Extract authenticated domain from auth results
   */
  private static extractAuthDomain(authResults: string): string | null {
    const match = authResults.match(/header\.from=([^\s;]+)/i);
    return match ? match[1].toLowerCase() : null;
  }

  /**
   * Check if domains match (including subdomains)
   */
  private static domainsMatch(domain1: string, domain2: string): boolean {
    return domain1 === domain2 || domain1.endsWith(domain2) || domain2.endsWith(domain1);
  }

  /**
   * Detect suspicious Reply-To addresses
   */
  static checkReplyToMismatch(headers: EmailHeaders): ThreatIndicator | null {
    const from = headers.from;
    const replyTo = headers['reply-to'];

    if (!from || !replyTo) return null;

    const fromDomain = this.extractDomainFromHeader(from);
    const replyDomain = this.extractDomainFromHeader(replyTo);

    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      return {
        type: 'header',
        description: 'Reply-To domain differs from sender domain',
        severity: 'medium',
        evidence: `From: ${fromDomain}, Reply-To: ${replyDomain}`,
        confidence: 0.7,
      };
    }

    return null;
  }
}
