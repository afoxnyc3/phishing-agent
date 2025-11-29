import { describe, it, expect } from '@jest/globals';
import {
  buildReplyHtml,
  buildErrorReplyHtml,
  createReplyMessage,
  __testEscapeHtml,
} from './email-reply-builder.js';

describe('email reply builder', () => {
  describe('escapeHtml', () => {
    it('escapes HTML entities in dynamic content', () => {
      const malicious = `<script>alert('x')</script>`;
      const escaped = __testEscapeHtml(malicious);
      expect(escaped).toBe('&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;');
    });

    it('escapes ampersands', () => {
      expect(__testEscapeHtml('foo & bar')).toBe('foo &amp; bar');
    });

    it('escapes double quotes', () => {
      expect(__testEscapeHtml('say "hello"')).toBe('say &quot;hello&quot;');
    });

    it('handles empty string', () => {
      expect(__testEscapeHtml('')).toBe('');
    });
  });

  describe('buildReplyHtml', () => {
    const createMockAnalysis = (overrides = {}) => ({
      messageId: 'msg-123',
      isPhishing: false,
      confidence: 0.85,
      riskScore: 3.5,
      severity: 'low' as const,
      indicators: [],
      recommendedActions: [],
      analysisTimestamp: new Date('2025-01-15T10:00:00Z'),
      analysisId: 'analysis-123',
      ...overrides,
    });

    it('renders safe verdict for non-phishing email', () => {
      const html = buildReplyHtml(createMockAnalysis({ isPhishing: false }));
      expect(html).toContain('EMAIL APPEARS SAFE');
      expect(html).toContain('#388E3C'); // Green color
    });

    it('renders phishing verdict for detected phishing', () => {
      const html = buildReplyHtml(createMockAnalysis({ isPhishing: true }));
      expect(html).toContain('PHISHING DETECTED');
      expect(html).toContain('#D32F2F'); // Red color
    });

    it('displays risk score correctly', () => {
      const html = buildReplyHtml(createMockAnalysis({ riskScore: 7.5 }));
      expect(html).toContain('7.5/10');
    });

    it('displays severity in uppercase', () => {
      const html = buildReplyHtml(createMockAnalysis({ severity: 'high' }));
      expect(html).toContain('HIGH');
    });

    it('displays confidence as percentage', () => {
      const html = buildReplyHtml(createMockAnalysis({ confidence: 0.95 }));
      expect(html).toContain('95%');
    });

    it('displays analysis ID', () => {
      const html = buildReplyHtml(createMockAnalysis({ analysisId: 'test-id-456' }));
      expect(html).toContain('test-id-456');
    });

    it('renders safe HTML with escaped indicators and actions', () => {
      const html = buildReplyHtml({
        messageId: '1',
        isPhishing: true,
        confidence: 0.9,
        riskScore: 9.1,
        severity: 'critical',
        indicators: [
          { type: 'content', description: `<b>bold</b>`, severity: 'high', evidence: '', confidence: 0.9 },
        ],
        recommendedActions: [
          {
            priority: 'high',
            action: 'alert',
            description: `<img src=x onerror=alert(1)>`,
            automated: false,
            requiresApproval: false,
          },
        ],
        analysisTimestamp: new Date(),
        analysisId: 'analysis-1',
      });

      expect(html).toContain('&lt;b&gt;bold&lt;/b&gt;');
      expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
      expect(html).not.toContain('<b>bold</b>');
    });

    it('limits indicators to top 5', () => {
      const indicators = Array(10)
        .fill(null)
        .map((_, i) => ({
          type: 'test',
          description: `Indicator ${i}`,
          severity: 'high' as const,
          evidence: '',
          confidence: 0.9,
        }));

      const html = buildReplyHtml(createMockAnalysis({ isPhishing: true, indicators }));

      expect(html).toContain('Indicator 0');
      expect(html).toContain('Indicator 4');
      expect(html).not.toContain('Indicator 5');
    });

    it('limits actions to top 3', () => {
      const actions = Array(6)
        .fill(null)
        .map((_, i) => ({
          priority: 'high' as const,
          action: 'test',
          description: `Action ${i}`,
          automated: false,
          requiresApproval: false,
        }));

      const html = buildReplyHtml(createMockAnalysis({ recommendedActions: actions }));

      expect(html).toContain('Action 0');
      expect(html).toContain('Action 2');
      expect(html).not.toContain('Action 3');
    });

    it('shows AI explanation when present', () => {
      const html = buildReplyHtml(
        createMockAnalysis({
          explanation: 'This email shows signs of credential harvesting.',
        })
      );
      expect(html).toContain('AI Analysis');
      expect(html).toContain('credential harvesting');
    });

    it('hides AI section when no explanation', () => {
      const html = buildReplyHtml(createMockAnalysis({ explanation: undefined }));
      expect(html).not.toContain('AI Analysis');
    });

    it('shows warning for phishing emails', () => {
      const html = buildReplyHtml(createMockAnalysis({ isPhishing: true }));
      expect(html).toContain('Do NOT click any links');
    });

    it('shows reassurance for safe emails', () => {
      const html = buildReplyHtml(createMockAnalysis({ isPhishing: false }));
      expect(html).toContain('appears legitimate');
    });
  });

  describe('buildErrorReplyHtml', () => {
    it('includes processing ID', () => {
      const html = buildErrorReplyHtml('proc-123');
      expect(html).toContain('proc-123');
    });

    it('contains error message', () => {
      const html = buildErrorReplyHtml('proc-123');
      expect(html).toContain('Analysis Error');
      expect(html).toContain('encountered an error');
    });

    it('includes styling', () => {
      const html = buildErrorReplyHtml('proc-123');
      expect(html).toContain('<style>');
      expect(html).toContain('error-box');
    });
  });

  describe('createReplyMessage', () => {
    const mockOriginalEmail = {
      id: 'test-graph-id',
      subject: 'Suspicious Email',
      from: { emailAddress: { address: 'sender@example.com' } },
    };

    it('creates reply with correct subject', () => {
      const message = createReplyMessage(mockOriginalEmail, '<html></html>', false);
      expect(message.message.subject).toBe('Re: Suspicious Email');
    });

    it('sets recipient to original sender', () => {
      const message = createReplyMessage(mockOriginalEmail, '<html></html>', false);
      expect(message.message.toRecipients[0].emailAddress.address).toBe('sender@example.com');
    });

    it('sets HTML content type', () => {
      const message = createReplyMessage(mockOriginalEmail, '<html>Test</html>', false);
      expect(message.message.body.contentType).toBe('HTML');
      expect(message.message.body.content).toBe('<html>Test</html>');
    });

    it('sets high importance for phishing', () => {
      const message = createReplyMessage(mockOriginalEmail, '<html></html>', true);
      expect(message.message.importance).toBe('high');
    });

    it('sets normal importance for safe emails', () => {
      const message = createReplyMessage(mockOriginalEmail, '<html></html>', false);
      expect(message.message.importance).toBe('normal');
    });

    it('handles missing subject', () => {
      const email = { ...mockOriginalEmail, subject: undefined };
      const message = createReplyMessage(email, '<html></html>', false);
      expect(message.message.subject).toBe('Re: (No Subject)');
    });
  });
});
