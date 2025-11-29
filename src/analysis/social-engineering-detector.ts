/**
 * Social Engineering Detector
 * Detects manipulation tactics in email content (urgency, credential harvesting, financial lures)
 * All functions are atomic (max 25 lines)
 */

import { ThreatIndicator } from '../lib/types.js';

export class SocialEngineeringDetector {
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

  /**
   * Detect urgency tactics
   */
  static detectUrgencyTactics(body: string): ThreatIndicator | null {
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
   * Detect credential harvesting attempts
   */
  static detectCredentialRequests(body: string): ThreatIndicator | null {
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
   * Detect financial lures and scams
   */
  static detectFinancialLures(body: string): ThreatIndicator | null {
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
}
