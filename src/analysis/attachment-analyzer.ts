/**
 * Attachment Analyzer
 * Detects suspicious attachments in phishing emails
 * All functions are atomic (max 25 lines)
 */

import { ThreatIndicator, EmailAttachment } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';

export interface AttachmentAnalysisResult {
  hasRiskyAttachments: boolean;
  indicators: ThreatIndicator[];
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  totalAttachments: number;
  riskyAttachments: number;
}

export class AttachmentAnalyzer {
  // Dangerous executable extensions (critical risk)
  private static readonly DANGEROUS_EXTENSIONS = [
    '.exe',
    '.scr',
    '.bat',
    '.cmd',
    '.vbs',
    '.vbe',
    '.js',
    '.jse',
    '.ws',
    '.wsf',
    '.msc',
    '.pif',
    '.com',
    '.hta',
    '.cpl',
    '.reg',
  ];

  // Macro-enabled document extensions (high risk)
  private static readonly MACRO_EXTENSIONS = ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam', '.ppam'];

  // Archive extensions that may hide malware (medium risk)
  private static readonly ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'];

  // Size thresholds
  private static readonly MIN_SUSPICIOUS_SIZE = 100; // Less than 100 bytes is suspicious
  private static readonly MAX_SAFE_SIZE = 25 * 1024 * 1024; // 25MB

  /**
   * Analyze attachments for security risks
   */
  static analyze(attachments?: EmailAttachment[]): AttachmentAnalysisResult {
    if (!attachments || attachments.length === 0) {
      return this.emptyResult();
    }

    const indicators: ThreatIndicator[] = [];
    let riskyCount = 0;

    for (const attachment of attachments) {
      const attachmentIndicators = this.analyzeAttachment(attachment);
      if (attachmentIndicators.length > 0) {
        indicators.push(...attachmentIndicators);
        riskyCount++;
      }
    }

    const riskLevel = this.calculateRiskLevel(indicators);
    this.logAnalysis(attachments.length, riskyCount, indicators.length);

    return {
      hasRiskyAttachments: indicators.length > 0,
      indicators,
      riskLevel,
      totalAttachments: attachments.length,
      riskyAttachments: riskyCount,
    };
  }

  /**
   * Return empty result when no attachments
   */
  private static emptyResult(): AttachmentAnalysisResult {
    return {
      hasRiskyAttachments: false,
      indicators: [],
      riskLevel: 'none',
      totalAttachments: 0,
      riskyAttachments: 0,
    };
  }

  /**
   * Analyze single attachment
   */
  private static analyzeAttachment(attachment: EmailAttachment): ThreatIndicator[] {
    const indicators: ThreatIndicator[] = [];

    this.checkDangerousExtension(attachment, indicators);
    this.checkMacroEnabled(attachment, indicators);
    this.checkDoubleExtension(attachment, indicators);
    this.checkArchiveFile(attachment, indicators);
    this.checkSizeAnomaly(attachment, indicators);

    return indicators;
  }

  /**
   * Check for dangerous executable extensions
   */
  private static checkDangerousExtension(attachment: EmailAttachment, indicators: ThreatIndicator[]): void {
    const ext = this.getExtension(attachment.filename);
    if (this.DANGEROUS_EXTENSIONS.includes(ext)) {
      indicators.push({
        type: 'attachment',
        description: `Dangerous file type detected: ${ext}`,
        severity: 'critical',
        evidence: `Filename: ${attachment.filename}`,
        confidence: 0.95,
      });
    }
  }

  /**
   * Check for macro-enabled documents
   */
  private static checkMacroEnabled(attachment: EmailAttachment, indicators: ThreatIndicator[]): void {
    const ext = this.getExtension(attachment.filename);
    if (this.MACRO_EXTENSIONS.includes(ext)) {
      indicators.push({
        type: 'attachment',
        description: `Macro-enabled document: ${ext}`,
        severity: 'high',
        evidence: `Filename: ${attachment.filename}`,
        confidence: 0.85,
      });
    }
  }

  /**
   * Check for double extension tricks (e.g., invoice.pdf.exe)
   */
  private static checkDoubleExtension(attachment: EmailAttachment, indicators: ThreatIndicator[]): void {
    const filename = attachment.filename.toLowerCase();
    const dangerousPattern = this.detectDoubleExtension(filename);

    if (dangerousPattern) {
      indicators.push({
        type: 'attachment',
        description: 'Double extension detected - possible executable disguise',
        severity: 'critical',
        evidence: `Filename: ${attachment.filename} (hidden: ${dangerousPattern})`,
        confidence: 0.98,
      });
    }
  }

  /**
   * Detect double extension pattern
   */
  private static detectDoubleExtension(filename: string): string | null {
    for (const dangerousExt of this.DANGEROUS_EXTENSIONS) {
      if (filename.endsWith(dangerousExt)) {
        const withoutDangerous = filename.slice(0, -dangerousExt.length);
        const previousExt = this.getExtension(withoutDangerous);
        if (previousExt && previousExt !== dangerousExt) {
          return dangerousExt;
        }
      }
    }
    return null;
  }

  /**
   * Check for archive files
   */
  private static checkArchiveFile(attachment: EmailAttachment, indicators: ThreatIndicator[]): void {
    const ext = this.getExtension(attachment.filename);
    if (this.ARCHIVE_EXTENSIONS.includes(ext)) {
      indicators.push({
        type: 'attachment',
        description: `Archive file may contain hidden malware: ${ext}`,
        severity: 'medium',
        evidence: `Filename: ${attachment.filename}, Size: ${this.formatSize(attachment.size)}`,
        confidence: 0.6,
      });
    }
  }

  /**
   * Check for file size anomalies
   */
  private static checkSizeAnomaly(attachment: EmailAttachment, indicators: ThreatIndicator[]): void {
    if (attachment.size < this.MIN_SUSPICIOUS_SIZE) {
      indicators.push({
        type: 'attachment',
        description: 'Suspiciously small file - may be a shortcut or script',
        severity: 'medium',
        evidence: `Filename: ${attachment.filename}, Size: ${attachment.size} bytes`,
        confidence: 0.7,
      });
    } else if (attachment.size > this.MAX_SAFE_SIZE) {
      indicators.push({
        type: 'attachment',
        description: 'Unusually large attachment',
        severity: 'low',
        evidence: `Filename: ${attachment.filename}, Size: ${this.formatSize(attachment.size)}`,
        confidence: 0.5,
      });
    }
  }

  /**
   * Get file extension from filename
   */
  private static getExtension(filename: string): string {
    const lastDot = filename.lastIndexOf('.');
    return lastDot >= 0 ? filename.slice(lastDot).toLowerCase() : '';
  }

  /**
   * Format size for display
   */
  private static formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  /**
   * Calculate overall risk level
   */
  private static calculateRiskLevel(indicators: ThreatIndicator[]): 'none' | 'low' | 'medium' | 'high' | 'critical' {
    if (indicators.length === 0) return 'none';

    const hasCritical = indicators.some((i) => i.severity === 'critical');
    const hasHigh = indicators.some((i) => i.severity === 'high');
    const hasMedium = indicators.some((i) => i.severity === 'medium');

    if (hasCritical) return 'critical';
    if (hasHigh) return 'high';
    if (hasMedium) return 'medium';
    return 'low';
  }

  /**
   * Log analysis results
   */
  private static logAnalysis(total: number, risky: number, indicatorCount: number): void {
    securityLogger.debug('Attachment analysis completed', {
      totalAttachments: total,
      riskyAttachments: risky,
      indicatorCount,
    });
  }
}
