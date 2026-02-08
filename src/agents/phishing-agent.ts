import { EmailAnalysisRequest, PhishingAnalysisResult, ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { EmailParser } from '../lib/email-parser.js';
import { HeaderValidator } from '../analysis/header-validator.js';
import { ContentAnalyzer, SuspiciousUrl } from '../analysis/content-analyzer.js';
import { AttachmentAnalyzer } from '../analysis/attachment-analyzer.js';
import { RiskScorer } from '../analysis/risk-scorer.js';
import { ThreatIntelService, ThreatIntelResult } from '../services/threat-intel.js';
import { shouldRunLlmAnalysis, generateThreatExplanation } from '../services/llm-analyzer.js';
import { getErrorMessage } from '../lib/errors.js';
import { setProcessingStage } from '../lib/correlation.js';

export class PhishingAgent {
  private initialized: boolean = false;
  private threatIntel: ThreatIntelService;

  constructor() {
    this.threatIntel = new ThreatIntelService();
  }

  async initialize(): Promise<void> {
    securityLogger.info('Phishing Agent initializing...');

    const threatIntelHealthy = await this.threatIntel.healthCheck();
    securityLogger.info('Phishing Agent initialized successfully', {
      threatIntelEnabled: threatIntelHealthy,
    });

    this.initialized = true;
  }

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

  private async performAnalysis(request: EmailAnalysisRequest, analysisId: string): Promise<PhishingAnalysisResult> {
    const headerResult = HeaderValidator.validate(request.headers);
    const senderDomain = EmailParser.extractDomain(request.sender);
    const contentResult = ContentAnalyzer.analyze(request.body || '', senderDomain);
    const attachmentResult = AttachmentAnalyzer.analyze(request.attachments);

    setProcessingStage('threat-intel');
    const threatIntelResult = await this.enrichWithThreatIntel(request, contentResult.suspiciousUrls);
    setProcessingStage('risk-scoring');
    const riskResult = RiskScorer.calculateRisk(headerResult, contentResult, attachmentResult);
    const enhancedScore = Math.min(10, riskResult.riskScore + threatIntelResult.riskContribution);

    const allIndicators = [...riskResult.indicators, ...threatIntelResult.indicators];
    const severity = this.determineFinalSeverity(
      riskResult.severity,
      enhancedScore,
      threatIntelResult.riskContribution
    );
    setProcessingStage('llm-analysis');
    const explanation = await this.generateExplanation(request, enhancedScore, allIndicators);

    securityLogger.info('Email analysis completed', {
      analysisId,
      messageId: request.messageId,
      isPhishing: enhancedScore >= 5.0,
      finalRiskScore: enhancedScore,
      severity,
      totalIndicators: allIndicators.length,
      attachmentRisk: attachmentResult.riskLevel,
      hasExplanation: !!explanation,
    });

    return {
      messageId: request.messageId,
      isPhishing: enhancedScore >= 5.0,
      confidence: riskResult.confidence,
      riskScore: enhancedScore,
      severity,
      indicators: allIndicators,
      recommendedActions: riskResult.recommendedActions,
      analysisTimestamp: new Date(),
      analysisId,
      explanation,
    };
  }

  private async generateExplanation(
    request: EmailAnalysisRequest,
    riskScore: number,
    indicators: ThreatIndicator[]
  ): Promise<string | undefined> {
    if (!shouldRunLlmAnalysis(riskScore)) return undefined;

    const result = await generateThreatExplanation({
      subject: request.subject,
      sender: request.sender,
      body: request.body || '',
      riskScore,
      indicators,
    });

    return result?.explanation;
  }

  private async enrichWithThreatIntel(
    request: EmailAnalysisRequest,
    suspiciousUrls: SuspiciousUrl[]
  ): Promise<ThreatIntelResult> {
    const senderIp = this.extractSenderIP(request.headers);
    const urls = suspiciousUrls.map((u) => u.url);

    try {
      return await this.threatIntel.enrichEmail(request.sender, senderIp, urls);
    } catch (error: unknown) {
      securityLogger.warn('Threat intel enrichment failed', { error: getErrorMessage(error) });
      return { indicators: [], riskContribution: 0 };
    }
  }

  private determineFinalSeverity(
    baseSeverity: 'low' | 'medium' | 'high' | 'critical',
    enhancedScore: number,
    threatIntelContribution: number
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (threatIntelContribution >= 2.0 && enhancedScore >= 8.0) return 'critical';
    if (threatIntelContribution >= 1.0 && enhancedScore >= 6.0) {
      return enhancedScore >= 8.0 ? 'critical' : 'high';
    }
    return baseSeverity;
  }

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

  private handleAnalysisError(
    request: EmailAnalysisRequest,
    analysisId: string,
    error: unknown
  ): PhishingAnalysisResult {
    const errorMsg = getErrorMessage(error);
    securityLogger.error('Email analysis failed', {
      analysisId,
      messageId: request.messageId,
      error: errorMsg,
    });
    return this.buildErrorResult(request.messageId, analysisId, errorMsg);
  }

  private buildErrorResult(messageId: string, analysisId: string, errorMsg: string): PhishingAnalysisResult {
    return {
      messageId,
      isPhishing: false,
      confidence: 0,
      riskScore: 0,
      severity: 'medium',
      indicators: [
        {
          type: 'behavioral' as const,
          severity: 'medium' as const,
          description: 'Analysis error - unable to complete security scan',
          evidence: errorMsg,
          confidence: 1.0,
        },
      ],
      recommendedActions: [
        {
          priority: 'medium' as const,
          action: 'flag_for_review',
          description: 'Manual review required due to analysis error',
          automated: false,
          requiresApproval: false,
        },
      ],
      analysisTimestamp: new Date(),
      analysisId,
    };
  }

  async healthCheck(): Promise<boolean> {
    try {
      const headers = {
        'message-id': '<test@example.com>',
        from: 'test@example.com',
        to: 'user@test.com',
        subject: 'Test',
        date: new Date().toISOString(),
      };
      HeaderValidator.validate(headers);
      ContentAnalyzer.analyze('test');
      AttachmentAnalyzer.analyze([]);
      await this.threatIntel.healthCheck();
      return true;
    } catch (error) {
      securityLogger.error('Health check failed', { error: getErrorMessage(error) });
      return false;
    }
  }

  async shutdown(): Promise<void> {
    securityLogger.info('Phishing Agent shutting down...');
    this.initialized = false;
  }
}
