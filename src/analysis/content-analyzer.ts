/* eslint-disable max-lines */
// TODO: Refactor this file to be under 200 lines (see GitHub issue)
/**
 * Content Analyzer
 * Detects phishing patterns in email body content
 * All functions are atomic (max 25 lines)
 */

import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { BRAND_TARGETS, TYPOSQUAT_PATTERNS } from './brand-detection-config.js';
import sanitizeHtml from 'sanitize-html';

export interface ContentAnalysisResult {
  hasPhishingPatterns: boolean;
  indicators: ThreatIndicator[];
  suspiciousUrls: SuspiciousUrl[];
  socialEngineeringTactics: string[];
  confidence: number;
}

export interface SuspiciousUrl {
  url: string;
  reason: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  isPhishing: boolean;
}

export class ContentAnalyzer {
  private static readonly URGENCY_KEYWORDS = [
    'urgent', 'immediate action', 'act now', 'expires today', 'limited time',
    'verify now', 'confirm immediately', 'suspended', 'locked', 'unusual activity',
    'security alert', 'verify your account', 'confirm your identity', 'update your information',
  ];

  private static readonly CREDENTIAL_REQUESTS = [
    'password', 'social security', 'ssn', 'credit card', 'bank account',
    'pin number', 'security code', 'cvv', 'login credentials',
    'username and password', 'account number', 'routing number',
  ];

  private static readonly FINANCIAL_LURES = [
    'you\'ve won', 'claim your prize', 'refund', 'tax return', 'inheritance',
    'lottery', 'free money', 'unclaimed funds', 'wire transfer', 'payment required',
  ];

  private static readonly SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  ];

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

      // Brand impersonation (requires both body and domain)
      if (senderDomain) {
        this.analyzeBrandImpersonation(trimmedBody, senderDomain, indicators);
      }
    }

    // Typosquatting can be detected without body content
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
   * Return empty analysis result
   */
  private static emptyResult(): ContentAnalysisResult {
    return {
      hasPhishingPatterns: false,
      indicators: [],
      suspiciousUrls: [],
      socialEngineeringTactics: [],
      confidence: 0,
    };
  }

  /**
   * Analyze for urgency tactics
   */
  private static analyzeUrgency(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const indicator = this.detectUrgencyTactics(body);
    if (indicator) {
      indicators.push(indicator);
      tactics.push('urgency');
    }
  }

  /**
   * Analyze for credential requests
   */
  private static analyzeCredentialRequests(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const indicator = this.detectCredentialRequests(body);
    if (indicator) {
      indicators.push(indicator);
      tactics.push('credential_harvesting');
    }
  }

  /**
   * Analyze for financial lures
   */
  private static analyzeFinancialLures(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const indicator = this.detectFinancialLures(body);
    if (indicator) {
      indicators.push(indicator);
      tactics.push('financial_lure');
    }
  }

  /**
   * Analyze URLs in body
   */
  private static analyzeUrls(body: string, indicators: ThreatIndicator[], suspiciousUrls: SuspiciousUrl[]): void {
    const urls = this.extractUrls(body);
    for (const url of urls) {
      const analysis = this.analyzeUrl(url);
      if (analysis.isPhishing) {
        suspiciousUrls.push(analysis);
        indicators.push({
          type: 'url',
          description: `Suspicious URL detected: ${analysis.reason}`,
          severity: analysis.severity,
          evidence: url,
          confidence: 0.8,
        });
      }
    }
  }

  /**
   * Analyze for mismatched links
   */
  private static analyzeMismatchedLinks(body: string, indicators: ThreatIndicator[], tactics: string[]): void {
    const mismatched = this.detectMismatchedLinks(body);
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
   * Calculate average confidence
   */
  private static calculateConfidence(indicators: ThreatIndicator[]): number {
    if (indicators.length === 0) return 0;
    return indicators.reduce((sum, ind) => sum + ind.confidence, 0) / indicators.length;
  }

  /**
   * Detect urgency tactics
   */
  private static detectUrgencyTactics(body: string): ThreatIndicator | null {
    const found = this.URGENCY_KEYWORDS.filter(kw => body.toLowerCase().includes(kw.toLowerCase()));

    if (found.length > 0) {
      return {
        type: 'content',
        description: 'Urgency and pressure tactics detected',
        severity: found.length > 2 ? 'high' : 'medium',
        evidence: `Found urgency keywords: ${found.slice(0, 3).join(', ')}`,
        confidence: Math.min(0.6 + (found.length * 0.1), 0.9),
      };
    }

    return null;
  }

  /**
   * Detect credential harvesting
   */
  private static detectCredentialRequests(body: string): ThreatIndicator | null {
    const found = this.CREDENTIAL_REQUESTS.filter(req => body.toLowerCase().includes(req.toLowerCase()));

    if (found.length > 0) {
      return {
        type: 'content',
        description: 'Credential harvesting attempt detected',
        severity: 'critical',
        evidence: `Requests for: ${found.slice(0, 3).join(', ')}`,
        confidence: 0.9,
      };
    }

    return null;
  }

  /**
   * Detect financial lures
   */
  private static detectFinancialLures(body: string): ThreatIndicator | null {
    const found = this.FINANCIAL_LURES.filter(lure => body.toLowerCase().includes(lure.toLowerCase()));

    if (found.length > 0) {
      return {
        type: 'content',
        description: 'Financial lure or scam detected',
        severity: 'high',
        evidence: `Found financial lures: ${found.slice(0, 3).join(', ')}`,
        confidence: 0.85,
      };
    }

    return null;
  }

  /**
   * Extract URLs from body
   */
  private static extractUrls(body: string): string[] {
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    return body.match(urlRegex) || [];
  }

  /**
   * Analyze individual URL
   */
  private static analyzeUrl(url: string): SuspiciousUrl {
    try {
      const urlObj = new URL(url);
      return this.checkUrlPatterns(url, urlObj);
    } catch {
      return { url, reason: 'Malformed URL', severity: 'medium', isPhishing: true };
    }
  }

  /**
   * Check URL for suspicious patterns
   */
  private static checkUrlPatterns(url: string, urlObj: URL): SuspiciousUrl {
    if (this.isUrlShortener(urlObj.hostname)) {
      return { url, reason: 'URL shortener detected', severity: 'medium', isPhishing: true };
    }
    if (this.isIpAddress(url)) {
      return { url, reason: 'IP address used instead of domain', severity: 'high', isPhishing: true };
    }
    if (this.hasSuspiciousTld(urlObj.hostname)) {
      return { url, reason: 'Suspicious TLD', severity: 'medium', isPhishing: true };
    }
    if (url.includes('@')) {
      return { url, reason: 'URL contains @ symbol', severity: 'critical', isPhishing: true };
    }

    return { url, reason: 'No issues detected', severity: 'low', isPhishing: false };
  }

  /**
   * Check if hostname is URL shortener
   */
  private static isUrlShortener(hostname: string): boolean {
    return this.SUSPICIOUS_DOMAINS.some(domain => hostname.includes(domain));
  }

  /**
   * Check if URL uses IP address
   */
  private static isIpAddress(url: string): boolean {
    return /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
  }

  /**
   * Check for suspicious TLD
   */
  private static hasSuspiciousTld(hostname: string): boolean {
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win'];
    return suspiciousTlds.some(tld => hostname.endsWith(tld));
  }

  /**
   * Detect mismatched links
   */
  private static detectMismatchedLinks(body: string): Array<{ text: string; url: string }> {
    const mismatches: Array<{ text: string; url: string }> = [];
    const linkRegex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>(.*?)<\/a>/gi;
    let match;

    while ((match = linkRegex.exec(body)) !== null) {
      const [, , url, text] = match;
      const cleanText = sanitizeHtml(text, { allowedTags: [], allowedAttributes: {} }).trim();

      if (this.isLinkMismatch(url, cleanText)) {
        mismatches.push({ text: cleanText, url });
      }
    }

    return mismatches;
  }

  /**
   * Check if link text and URL mismatch
   */
  private static isLinkMismatch(url: string, text: string): boolean {
    if (!text.startsWith('http') && !text.includes('www.')) {
      return false;
    }

    try {
      const textUrl = text.startsWith('http') ? text : `https://${text}`;
      const hrefUrl = url.startsWith('http') ? url : `https://${url}`;
      const textDomain = new URL(textUrl).hostname;
      const hrefDomain = new URL(hrefUrl).hostname;
      return textDomain !== hrefDomain;
    } catch {
      return true; // Invalid URLs are suspicious
    }
  }

  /**
   * Analyze brand impersonation
   */
  private static analyzeBrandImpersonation(body: string, fromDomain: string, indicators: ThreatIndicator[]): void {
    const indicator = this.detectBrandImpersonation(body, fromDomain);
    if (indicator) {
      indicators.push(indicator);
    }
  }

  /**
   * Analyze typosquatting
   */
  private static analyzeTyposquatting(fromDomain: string, indicators: ThreatIndicator[]): void {
    const indicator = this.detectTyposquatting(fromDomain);
    if (indicator) {
      indicators.push(indicator);
    }
  }

  /**
   * Detect brand impersonation (20 most targeted brands)
   */
  static detectBrandImpersonation(body: string, fromDomain: string): ThreatIndicator | null {
    for (const brand of BRAND_TARGETS) {
      const regex = new RegExp(`\\b${brand.name.toLowerCase()}\\b`, 'i');
      if (regex.test(body) && !fromDomain.toLowerCase().includes(brand.domain)) {
        return {
          type: 'sender',
          description: `Possible ${brand.name} brand impersonation`,
          severity: 'critical',
          evidence: `Email mentions "${brand.name}" but sender is "${fromDomain}"`,
          confidence: 0.95,
        };
      }
    }

    return null;
  }

  /**
   * Detect typosquatting in domain (character substitution: 0→o, 1→l, 3→e)
   */
  static detectTyposquatting(fromDomain: string): ThreatIndicator | null {
    const lowercaseDomain = fromDomain.toLowerCase();

    for (const { pattern, brand } of TYPOSQUAT_PATTERNS) {
      if (pattern.test(lowercaseDomain)) {
        return {
          type: 'sender',
          description: `Typosquatting detected: ${brand} domain lookalike`,
          severity: 'critical',
          evidence: `Domain "${fromDomain}" uses character substitution to mimic ${brand}`,
          confidence: 0.98,
        };
      }
    }

    return null;
  }
}
