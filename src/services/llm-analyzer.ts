/**
 * LLM-Enhanced Analysis Service
 * Uses Claude to generate natural language threat explanations
 * Triggered for borderline cases (score 4-6) or when demo mode is enabled
 */

import Anthropic from '@anthropic-ai/sdk';
import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';

export interface LlmAnalysisRequest {
  subject: string;
  sender: string;
  body: string;
  riskScore: number;
  indicators: ThreatIndicator[];
}

export interface LlmAnalysisResult {
  explanation: string;
  processingTimeMs: number;
}

/**
 * Check if LLM analysis should run
 */
export function shouldRunLlmAnalysis(riskScore: number): boolean {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return false;

  const demoMode = process.env.LLM_DEMO_MODE === 'true';
  if (demoMode) return true;

  // Only run for borderline cases (score 4-6) to control cost
  return riskScore >= 4 && riskScore <= 6;
}

/**
 * Generate natural language threat explanation using Claude
 */
export async function generateThreatExplanation(
  request: LlmAnalysisRequest
): Promise<LlmAnalysisResult | null> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    securityLogger.debug('LLM analysis skipped: no API key configured');
    return null;
  }

  const startTime = Date.now();

  try {
    const client = new Anthropic({ apiKey });
    const prompt = buildPrompt(request);

    const response = await client.messages.create({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }],
    });

    const explanation = extractExplanation(response);
    const processingTimeMs = Date.now() - startTime;

    securityLogger.info('LLM analysis completed', {
      riskScore: request.riskScore,
      processingTimeMs,
      explanationLength: explanation.length,
    });

    return { explanation, processingTimeMs };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    securityLogger.warn('LLM analysis failed', { error: errorMessage });
    return null;
  }
}

/**
 * Build prompt for threat explanation
 */
function buildPrompt(request: LlmAnalysisRequest): string {
  const indicatorList = request.indicators
    .slice(0, 5)
    .map((i) => `- ${i.description} (${i.severity})`)
    .join('\n');

  return `You are a cybersecurity expert analyzing a suspicious email. Provide a brief, clear explanation of why this email may be dangerous.

EMAIL DETAILS:
Subject: ${request.subject}
Sender: ${request.sender}
Risk Score: ${request.riskScore}/10

DETECTED INDICATORS:
${indicatorList || 'None detected'}

EMAIL BODY PREVIEW:
${(request.body || '').substring(0, 500)}

Provide a 2-3 sentence explanation suitable for a non-technical user. Focus on the most concerning aspects and explain WHY it's suspicious. Be direct and actionable.`;
}

/**
 * Extract explanation text from Claude response
 */
function extractExplanation(response: Anthropic.Message): string {
  const textBlock = response.content.find((block) => block.type === 'text');
  return textBlock?.type === 'text' ? textBlock.text : 'Unable to generate explanation.';
}
