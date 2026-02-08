/**
 * LLM-Enhanced Analysis Service
 * Uses Claude to generate natural language threat explanations
 * Triggered for borderline cases (score 4-6) or when demo mode is enabled
 *
 * Production Features:
 * - Retry logic with exponential backoff (p-retry)
 * - Circuit breaker pattern (opossum)
 * - Configurable timeout
 * - Health check integration
 */

import Anthropic from '@anthropic-ai/sdk';
import CircuitBreaker from 'opossum';
import pRetry from 'p-retry';
import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';
import { getErrorMessage } from '../lib/errors.js';

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

export interface LlmServiceStatus {
  enabled: boolean;
  circuitBreakerState: string;
  consecutiveFailures: number;
}

// Singleton circuit breaker instance
let circuitBreaker: CircuitBreaker<[LlmAnalysisRequest], LlmAnalysisResult | null> | null = null;
let consecutiveFailures = 0;

/**
 * Get or create the circuit breaker instance
 */
function getCircuitBreaker(): CircuitBreaker<[LlmAnalysisRequest], LlmAnalysisResult | null> {
  if (!circuitBreaker) {
    circuitBreaker = new CircuitBreaker(callAnthropicWithRetry, {
      timeout: config.llm.timeoutMs,
      errorThresholdPercentage: 50,
      volumeThreshold: config.llm.circuitBreakerThreshold,
      resetTimeout: config.llm.circuitBreakerResetMs,
      name: 'llm-analyzer',
    });

    circuitBreaker.on('success', () => {
      consecutiveFailures = 0;
    });

    circuitBreaker.on('failure', () => {
      consecutiveFailures++;
    });

    circuitBreaker.on('open', () => {
      securityLogger.warn('LLM circuit breaker opened', {
        consecutiveFailures,
        resetTimeoutMs: config.llm.circuitBreakerResetMs,
      });
    });

    circuitBreaker.on('halfOpen', () => {
      securityLogger.info('LLM circuit breaker half-open, testing connection');
    });

    circuitBreaker.on('close', () => {
      securityLogger.info('LLM circuit breaker closed, service restored');
      consecutiveFailures = 0;
    });
  }

  return circuitBreaker;
}

/**
 * Check if LLM analysis should run
 */
export function shouldRunLlmAnalysis(riskScore: number): boolean {
  const apiKey = config.llm.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return false;

  const demoMode = config.llm.demoMode || process.env.LLM_DEMO_MODE === 'true';
  if (demoMode) return true;

  // Only run for borderline cases (score 4-6) to control cost
  return riskScore >= 4 && riskScore <= 6;
}

/**
 * Make single API call to Claude
 */
async function makeApiCall(apiKey: string, prompt: string): Promise<Anthropic.Message> {
  const client = new Anthropic({ apiKey });
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.llm.timeoutMs);

  try {
    const response = await client.messages.create({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }],
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

/**
 * Determine if error is retryable
 */
function isRetryableError(error: Error): boolean {
  const msg = error.message?.toLowerCase() || '';
  if (msg.includes('invalid api key')) return false;
  if (msg.includes('unauthorized')) return false;
  return true;
}

/**
 * Call Anthropic API with retry logic
 */
async function callAnthropicWithRetry(request: LlmAnalysisRequest): Promise<LlmAnalysisResult | null> {
  const apiKey = config.llm.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    securityLogger.debug('LLM analysis skipped: no API key configured');
    return null;
  }

  const startTime = Date.now();
  const prompt = buildPrompt(request);

  const result = await pRetry(() => makeApiCall(apiKey, prompt), {
    retries: config.llm.retryAttempts,
    onFailedAttempt: (error) => {
      securityLogger.warn('LLM API call failed, retrying', {
        attemptNumber: error.attemptNumber,
        retriesLeft: error.retriesLeft,
        error: error.message,
      });
    },
    shouldRetry: isRetryableError,
  });

  const explanation = extractExplanation(result);
  const processingTimeMs = Date.now() - startTime;

  securityLogger.info('LLM analysis completed', {
    riskScore: request.riskScore,
    processingTimeMs,
    explanationLength: explanation.length,
  });

  return { explanation, processingTimeMs };
}

/**
 * Generate natural language threat explanation using Claude
 * Protected by circuit breaker and retry logic
 */
export async function generateThreatExplanation(request: LlmAnalysisRequest): Promise<LlmAnalysisResult | null> {
  const apiKey = config.llm.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    securityLogger.debug('LLM analysis skipped: no API key configured');
    return null;
  }

  try {
    const breaker = getCircuitBreaker();
    return await breaker.fire(request);
  } catch (error) {
    const errorMessage = getErrorMessage(error);

    // Check if circuit is open
    if (errorMessage.includes('Breaker is open')) {
      securityLogger.warn('LLM analysis skipped: circuit breaker open');
      return null;
    }

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

/**
 * Get circuit breaker state as string
 */
function getCircuitBreakerState(
  breaker: CircuitBreaker<[LlmAnalysisRequest], LlmAnalysisResult | null> | null
): string {
  if (!breaker) return 'not-initialized';
  if (breaker.opened) return 'open';
  if (breaker.halfOpen) return 'half-open';
  if (breaker.closed) return 'closed';
  return 'unknown';
}

/**
 * Get LLM service status for health checks
 */
export function getLlmServiceStatus(): LlmServiceStatus {
  const apiKey = config.llm.apiKey || process.env.ANTHROPIC_API_KEY;
  const breaker = circuitBreaker;

  return {
    enabled: !!apiKey,
    circuitBreakerState: getCircuitBreakerState(breaker),
    consecutiveFailures,
  };
}

/**
 * Check if LLM service is healthy
 */
export async function healthCheck(): Promise<boolean> {
  const apiKey = config.llm.apiKey || process.env.ANTHROPIC_API_KEY;

  // If not configured, that's OK - LLM is optional
  if (!apiKey) return true;

  // If circuit breaker is open, service is unhealthy
  const breaker = circuitBreaker;
  if (breaker && breaker.opened) {
    return false;
  }

  return true;
}

/**
 * Reset circuit breaker (for testing/recovery)
 */
export function resetCircuitBreaker(): void {
  if (circuitBreaker) {
    circuitBreaker.close();
    consecutiveFailures = 0;
    securityLogger.info('LLM circuit breaker manually reset');
  }
}
