/**
 * URL Analyzer
 * Detects suspicious URLs and mismatched links in email content
 * All functions are atomic (max 25 lines)
 */

import { ThreatIndicator } from '../lib/types.js';
import sanitizeHtml from 'sanitize-html';

export interface SuspiciousUrl {
  url: string;
  reason: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  isPhishing: boolean;
}

export class UrlAnalyzer {
  private static readonly SUSPICIOUS_DOMAINS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];

  /**
   * Extract URLs from body
   */
  static extractUrls(body: string): string[] {
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    return body.match(urlRegex) || [];
  }

  /**
   * Analyze individual URL
   */
  static analyzeUrl(url: string): SuspiciousUrl {
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
      return {
        url,
        reason: 'IP address used instead of domain',
        severity: 'high',
        isPhishing: true,
      };
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
    return this.SUSPICIOUS_DOMAINS.some((domain) => hostname.includes(domain));
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
    return suspiciousTlds.some((tld) => hostname.endsWith(tld));
  }

  /**
   * Detect mismatched links (display text differs from href)
   */
  static detectMismatchedLinks(body: string): Array<{ text: string; url: string }> {
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
   * Analyze URLs and return indicators
   */
  static analyzeUrls(body: string): {
    indicators: ThreatIndicator[];
    suspiciousUrls: SuspiciousUrl[];
  } {
    const indicators: ThreatIndicator[] = [];
    const suspiciousUrls: SuspiciousUrl[] = [];
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

    return { indicators, suspiciousUrls };
  }
}
