import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Create hoisted mock functions for use inside vi.mock factories
const { mockMessagesCreate, circuitState } = vi.hoisted(() => ({
  mockMessagesCreate: vi.fn<any>(),
  circuitState: { opened: false },
}));

// Mock Anthropic SDK
vi.mock('@anthropic-ai/sdk', () => ({
  default: class MockAnthropic {
    messages = { create: mockMessagesCreate };
  },
}));

// Mock p-retry to just call the function directly (bypass retry logic in tests)
vi.mock('p-retry', () => ({
  default: vi.fn<any>().mockImplementation(async (fn: () => Promise<unknown>) => fn()),
}));

// Mock opossum circuit breaker to pass through to actual function
vi.mock('opossum', () => ({
  default: class MockCircuitBreaker {
    on = vi.fn();
    halfOpen = false;
    close = vi.fn();
    fire: (...args: any[]) => Promise<any>;

    constructor(fn: (...args: any[]) => Promise<any>) {
      this.fire = async (...args: any[]) => {
        if (circuitState.opened) throw new Error('Breaker is open');
        return fn(...args);
      };
    }

    get opened() {
      return circuitState.opened;
    }
    get closed() {
      return !circuitState.opened;
    }
  },
}));

vi.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../lib/config.js', () => ({
  config: {
    server: {
      environment: 'test',
    },
    llm: {
      apiKey: undefined,
      demoMode: false,
      timeoutMs: 10000,
      retryAttempts: 3,
      circuitBreakerThreshold: 5,
      circuitBreakerResetMs: 60000,
    },
  },
}));

// Import after mocks are set up
const { shouldRunLlmAnalysis, generateThreatExplanation, getLlmServiceStatus, healthCheck } =
  await import('./llm-analyzer.js');

describe('LlmAnalyzer', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    circuitState.opened = false;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('shouldRunLlmAnalysis', () => {
    it('should return false when ANTHROPIC_API_KEY is not set', () => {
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(5.0)).toBe(false);
    });

    it('should return true when in demo mode with API key', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      process.env.LLM_DEMO_MODE = 'true';

      expect(shouldRunLlmAnalysis(2.0)).toBe(true);
    });

    it('should return true for borderline score (4.0) with API key', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(4.0)).toBe(true);
    });

    it('should return true for borderline score (5.0) with API key', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(5.0)).toBe(true);
    });

    it('should return true for borderline score (6.0) with API key', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(6.0)).toBe(true);
    });

    it('should return false for low score (3.9) without demo mode', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(3.9)).toBe(false);
    });

    it('should return false for high score (6.1) without demo mode', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(6.1)).toBe(false);
    });

    it('should return false for critical score (9.0) without demo mode', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(9.0)).toBe(false);
    });

    it('should return true for any score in demo mode', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      process.env.LLM_DEMO_MODE = 'true';

      expect(shouldRunLlmAnalysis(0)).toBe(true);
      expect(shouldRunLlmAnalysis(3)).toBe(true);
      expect(shouldRunLlmAnalysis(7)).toBe(true);
      expect(shouldRunLlmAnalysis(10)).toBe(true);
    });

    it('should return false at exact boundary (3.99)', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(3.99)).toBe(false);
    });

    it('should return false at exact upper boundary (6.01)', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      delete process.env.LLM_DEMO_MODE;

      expect(shouldRunLlmAnalysis(6.01)).toBe(false);
    });
  });

  describe('generateThreatExplanation', () => {
    const validRequest = {
      subject: 'URGENT: Account Suspended',
      sender: 'security@paypa1.com',
      body: 'Click here to verify your account immediately.',
      riskScore: 7.5,
      indicators: [
        {
          type: 'content' as const,
          description: 'Urgency keywords detected',
          severity: 'high' as const,
          evidence: 'URGENT, immediately',
          confidence: 0.9,
        },
        {
          type: 'sender' as const,
          description: 'Typosquatting domain detected',
          severity: 'critical' as const,
          evidence: 'paypa1.com looks like paypal.com',
          confidence: 0.95,
        },
      ],
    };

    it('should return null when API key is not configured', async () => {
      delete process.env.ANTHROPIC_API_KEY;

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });

    it('should call Anthropic API with correct model', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'This is a phishing email.' }],
      });

      await generateThreatExplanation(validRequest);

      expect(mockMessagesCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          model: 'claude-3-5-haiku-20241022',
          max_tokens: 300,
        }),
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      );
    });

    it('should include subject in prompt', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Analysis result' }],
      });

      await generateThreatExplanation(validRequest);

      expect(mockMessagesCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              role: 'user',
              content: expect.stringContaining('URGENT: Account Suspended'),
            }),
          ]),
        }),
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      );
    });

    it('should return explanation and processing time on success', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'This email shows clear signs of phishing.' }],
      });

      const result = await generateThreatExplanation(validRequest);

      expect(result).not.toBeNull();
      expect(result?.explanation).toBe('This email shows clear signs of phishing.');
      expect(result?.processingTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should handle API errors gracefully', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockRejectedValue(new Error('API rate limit exceeded'));

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });

    it('should handle non-Error exceptions', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockRejectedValue('String error');

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });

    it('should handle response with no text content', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'tool_use' }],
      });

      const result = await generateThreatExplanation(validRequest);

      expect(result?.explanation).toBe('Unable to generate explanation.');
    });

    it('should handle empty response content array', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockResolvedValue({
        content: [],
      });

      const result = await generateThreatExplanation(validRequest);

      expect(result?.explanation).toBe('Unable to generate explanation.');
    });

    it('should handle empty body gracefully', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      const requestWithEmptyBody = {
        ...validRequest,
        body: '',
      };

      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Analysis result' }],
      });

      const result = await generateThreatExplanation(requestWithEmptyBody);

      expect(result).not.toBeNull();
    });

    it('should handle network timeout errors', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      const timeoutError = new Error('Request timeout');
      timeoutError.name = 'TimeoutError';
      mockMessagesCreate.mockRejectedValue(timeoutError);

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });

    it('should handle authentication errors', async () => {
      process.env.ANTHROPIC_API_KEY = 'invalid-key';

      mockMessagesCreate.mockRejectedValue(new Error('Invalid API key'));

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });

    it('should handle rate limit errors', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';

      mockMessagesCreate.mockRejectedValue(new Error('Rate limit exceeded'));

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });

    it('should return null when circuit breaker is open', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-api-key';
      circuitState.opened = true;

      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Analysis result' }],
      });

      const result = await generateThreatExplanation(validRequest);

      expect(result).toBeNull();
    });
  });

  describe('getLlmServiceStatus', () => {
    it('should return disabled when no API key', () => {
      delete process.env.ANTHROPIC_API_KEY;

      const status = getLlmServiceStatus();

      expect(status.enabled).toBe(false);
    });

    it('should return enabled when API key is set', () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';

      const status = getLlmServiceStatus();

      expect(status.enabled).toBe(true);
    });

    it('should return consecutiveFailures count', () => {
      const status = getLlmServiceStatus();

      expect(typeof status.consecutiveFailures).toBe('number');
    });

    it('should return circuitBreakerState', () => {
      const status = getLlmServiceStatus();

      expect(typeof status.circuitBreakerState).toBe('string');
    });
  });

  describe('healthCheck', () => {
    it('should return true when API key is not configured', async () => {
      delete process.env.ANTHROPIC_API_KEY;

      const healthy = await healthCheck();

      expect(healthy).toBe(true);
    });

    it('should return true when API key is configured and circuit is closed', async () => {
      process.env.ANTHROPIC_API_KEY = 'test-key';
      circuitState.opened = false;

      const healthy = await healthCheck();

      expect(healthy).toBe(true);
    });
  });
});
