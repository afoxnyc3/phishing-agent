/**
 * Brand Detector
 * Detects brand impersonation and typosquatting in email sender domains
 * All functions are atomic (max 25 lines)
 */

import { ThreatIndicator } from '../lib/types.js';
import { BRAND_TARGETS, TYPOSQUAT_PATTERNS } from './brand-detection-config.js';

export class BrandDetector {
  /**
   * Detect brand impersonation (email mentions brand but sender domain doesn't match)
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
