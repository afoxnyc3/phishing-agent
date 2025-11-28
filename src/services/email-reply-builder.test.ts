import { buildReplyHtml, __testEscapeHtml } from './email-reply-builder.js';

describe('email reply builder', () => {
  it('escapes HTML entities in dynamic content', () => {
    const malicious = `<script>alert('x')</script>`;
    const escaped = __testEscapeHtml(malicious);
    expect(escaped).toBe('&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;');
  });

  it('renders safe HTML with escaped indicators and actions', () => {
    const html = buildReplyHtml({
      messageId: '1',
      isPhishing: true,
      confidence: 0.9,
      riskScore: 9.1,
      severity: 'critical',
      indicators: [{ type: 'content', description: `<b>bold</b>`, severity: 'high', evidence: '', confidence: 0.9 }],
      recommendedActions: [{
        priority: 'high',
        action: 'alert',
        description: `<img src=x onerror=alert(1)>`,
        automated: false,
        requiresApproval: false,
      }],
      analysisTimestamp: new Date(),
      analysisId: 'analysis-1',
    });

    expect(html).toContain('&lt;b&gt;bold&lt;/b&gt;');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<b>bold</b>');
  });
});
