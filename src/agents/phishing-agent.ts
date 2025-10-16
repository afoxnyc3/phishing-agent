/**
 * Phishing Agent
 * Orchestrates email phishing detection pipeline
 * All functions are atomic (max 25 lines)
 */

import { EmailAnalysisRequest, PhishingAnalysisResult, ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { EmailParser } from '../lib/email-parser.js';
import { HeaderValidator } from '../analysis/header-validator.js';
import { ContentAnalyzer } from '../analysis/content-analyzer.js';
import { RiskScorer } from '../analysis/risk-scorer.js';
import { ThreatIntelService } from '../services/threat-intel.js';

export class PhishingAgent {
  private initialized: boolean = false;
  private threatIntel: ThreatIntelService;

  constructor() {
    this.threatIntel = new ThreatIntelService();
  }

  /**
   * Initialize the agent
   */
  async initialize(): Promise<void> {
    securityLogger.info('Phishing Agent initializing...');

    const threatIntelHealthy = await this.threatIntel.healthCheck();
    securityLogger.info('Phishing Agent initialized successfully', {
      threatIntelEnabled: threatIntelHealthy,
    });

    this.initialized = true;
  }

  /**
   * Analyze email for phishing indicators
   */
  async analyzeEmail(request: EmailAnalysisRequest): Promise<PhishingAnalysisResult> {
    if (!this.initialized) {
      throw new Error('PhishingAgent not initialized. Call initialize() first.');
    }

    const analysisId = `analysis-${Date.now()}-${Math.random().toString(36).substring(7)}`;

    securityLogger.info('Starting email analysis', {
      messageId: request.messageId,
      analysisId,
      sender: request.sender,
    });

    try {
      return await this.performAnalysis(request, analysisId);
    } catch (error) {
      return this.handleAnalysisError(request, analysisId, error);
    }
  }

  /**
   * Perform email analysis
   */
  private async performAnalysis(request: EmailAnalysisRequest, analysisId: string): Promise<PhishingAnalysisResult> {
    // Step 1: Validate headers
    const headerResult = HeaderValidator.validate(request.headers);
    this.logHeaderResult(analysisId, headerResult);

    // Step 2: Analyze content
    const contentResult = this.analyzeContent(request, analysisId);

    // Step 3: Enrich with threat intelligence
    const threatIntelResult = await this.enrichWithThreatIntel(request, contentResult.suspiciousUrls);
    this.logThreatIntelResult(analysisId, threatIntelResult);

    // Step 4: Calculate risk score
    const riskResult = RiskScorer.calculateRisk(headerResult, contentResult);
    const enhancedRiskScore = Math.min(10, riskResult.riskScore + threatIntelResult.riskContribution);

    // Step 5: Combine indicators and determine final severity
    const allIndicators = [...riskResult.indicators, ...threatIntelResult.indicators];
    const finalSeverity = this.determineFinalSeverity(
      riskResult.severity,
      enhancedRiskScore,
      threatIntelResult.riskContribution
    );

    this.logFinalResult(analysisId, request, riskResult, enhancedRiskScore, finalSeverity, allIndicators);

    return {
      messageId: request.messageId,
      isPhishing: enhancedRiskScore >= 5.0,
      confidence: riskResult.confidence,
      riskScore: enhancedRiskScore,
      severity: finalSeverity,
      indicators: allIndicators,
      recommendedActions: riskResult.recommendedActions,
      analysisTimestamp: new Date(),
      analysisId,
    };
  }

  /**
   * Analyze email content
   */
  private analyzeContent(request: EmailAnalysisRequest, analysisId: string): any {
    const body = request.body || '';
    const contentResult = ContentAnalyzer.analyze(body);

    // Check for brand impersonation
    const senderDomain = EmailParser.extractDomain(request.sender);
    if (body && senderDomain) {
      const brandIndicator = ContentAnalyzer.detectBrandImpersonation(body, senderDomain);
      if (brandIndicator) {
        contentResult.indicators.push(brandIndicator);
        contentResult.hasPhishingPatterns = true;
      }
    }

    securityLogger.debug('Content analysis completed', {
      analysisId,
      hasPhishingPatterns: contentResult.hasPhishingPatterns,
      indicatorCount: contentResult.indicators.length,
      suspiciousUrlCount: contentResult.suspiciousUrls.length,
    });

    return contentResult;
  }

  /**
   * Enrich with threat intelligence
   */
  private async enrichWithThreatIntel(request: EmailAnalysisRequest, suspiciousUrls: any[]): Promise<any> {
    const senderIp = this.extractSenderIP(request.headers);
    const urls = suspiciousUrls.map(u => u.url);

    try {
      return await this.threatIntel.enrichEmail(request.sender, senderIp, urls);
    } catch (error: any) {
      securityLogger.warn('Threat intel enrichment failed', { error: error.message });
      return { indicators: [], riskContribution: 0 };
    }
  }

  /**
   * Determine final severity with threat intel boost
   */
  private determineFinalSeverity(
    baseSeverity: string,
    enhancedScore: number,
    threatIntelContribution: number
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (threatIntelContribution >= 2.0 && enhancedScore >= 8.0) {
      return 'critical';
    }
    if (threatIntelContribution >= 1.0 && enhancedScore >= 6.0) {
      return enhancedScore >= 8.0 ? 'critical' : 'high';
    }
    return baseSeverity as any;
  }

  /**
   * Extract sender IP from headers
   */
  private extractSenderIP(headers: Record<string, string | undefined>): string | null {
    const received = headers['received'] || headers['Received'];
    if (received) {
      const ipMatch = received.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
      if (ipMatch) return ipMatch[1];
    }

    const originatingIP = headers['x-originating-ip'];
    if (originatingIP) {
      const ipMatch = originatingIP.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (ipMatch) return ipMatch[1];
    }

    return null;
  }

  /**
   * Log header validation result
   */
  private logHeaderResult(analysisId: string, result: any): void {
    securityLogger.debug('Header validation completed', {
      analysisId,
      isValid: result.isValid,
      indicatorCount: result.indicators.length,
    });
  }

  /**
   * Log threat intel result
   */
  private logThreatIntelResult(analysisId: string, result: any): void {
    securityLogger.debug('Threat intelligence enrichment completed', {
      analysisId,
      indicatorsAdded: result.indicators.length,
      riskContribution: result.riskContribution,
    });
  }

  /**
   * Log final analysis result
   */
  private logFinalResult(
    analysisId: string,
    request: EmailAnalysisRequest,
    riskResult: any,
    enhancedScore: number,
    severity: string,
    indicators: ThreatIndicator[]
  ): void {
    securityLogger.info('Email analysis completed', {
      analysisId,
      messageId: request.messageId,
      isPhishing: riskResult.isPhishing,
      baseRiskScore: riskResult.riskScore,
      finalRiskScore: enhancedScore,
      severity,
      totalIndicators: indicators.length,
    });
  }

  /**
   * Handle analysis error
   */
  private handleAnalysisError(request: EmailAnalysisRequest, analysisId: string, error: any): PhishingAnalysisResult {
    securityLogger.error('Email analysis failed', {
      analysisId,
      messageId: request.messageId,
      error: error instanceof Error ? error.message : String(error),
    });

    return {
      messageId: request.messageId,
      isPhishing: false,
      confidence: 0,
      riskScore: 0,
      severity: 'medium',
      indicators: [{
        type: 'behavioral',
        description: 'Analysis error - unable to complete security scan',
        severity: 'medium',
        evidence: error instanceof Error ? error.message : 'Unknown error',
        confidence: 1.0,
      }],
      recommendedActions: [{
        priority: 'medium',
        action: 'flag_for_review',
        description: 'Manual review required due to analysis error',
        automated: false,
        requiresApproval: false,
      }],
      analysisTimestamp: new Date(),
      analysisId,
    };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      const testHeaders = {
        'message-id': '<test@example.com>',
        from: 'test@example.com',
        to: 'user@test.com',
        subject: 'Test',
        date: new Date().toISOString(),
      };

      HeaderValidator.validate(testHeaders);
      ContentAnalyzer.analyze('test');
      await this.threatIntel.healthCheck();

      return true;
    } catch (error) {
      securityLogger.error('Health check failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Shutdown
   */
  async shutdown(): Promise<void> {
    securityLogger.info('Phishing Agent shutting down...');
    this.initialized = false;
  }
}
