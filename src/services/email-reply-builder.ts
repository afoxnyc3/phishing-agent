/**
 * Email Reply Builder
 * Builds HTML email replies with analysis results
 * All functions are atomic (max 25 lines)
 */

import { PhishingAnalysisResult } from '../lib/types.js';

/**
 * Build HTML reply body
 */
export function buildReplyHtml(analysis: PhishingAnalysisResult): string {
  const verdict = analysis.isPhishing ? '🚨 PHISHING DETECTED' : '✅ EMAIL APPEARS SAFE';
  const color = analysis.isPhishing ? '#D32F2F' : '#388E3C';
  const indicatorsList = buildIndicatorsList(analysis);
  const actionsList = buildActionsList(analysis);

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background-color: ${color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .header h1 { margin: 0; font-size: 24px; }
    .content { background-color: #f5f5f5; padding: 20px; border-radius: 0 0 8px 8px; }
    .section { margin-bottom: 20px; }
    .section h2 { color: #1976D2; font-size: 18px; margin-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; }
    td { padding: 8px 0; }
    td:first-child { font-weight: 600; width: 150px; }
    pre { background-color: #fff; padding: 10px; border-left: 3px solid #1976D2; overflow-x: auto; font-size: 11px; }
    .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>${verdict}</h1></div>
    <div class="content">
      <div class="section">
        <h2>Risk Assessment</h2>
        <table>
          <tr><td>Risk Score:</td><td>${escapeHtml(analysis.riskScore.toFixed(1))}/10</td></tr>
          <tr><td>Severity:</td><td>${escapeHtml(analysis.severity.toUpperCase())}</td></tr>
          <tr><td>Confidence:</td><td>${escapeHtml((analysis.confidence * 100).toFixed(0))}%</td></tr>
          <tr><td>Analysis ID:</td><td>${escapeHtml(analysis.analysisId)}</td></tr>
        </table>
      </div>
      ${analysis.isPhishing && analysis.indicators.length > 0 ? `<div class="section"><h2>Threat Indicators</h2><pre>${indicatorsList}</pre></div>` : ''}
      ${analysis.explanation ? `<div class="section" style="background-color: #E3F2FD; padding: 15px; border-radius: 4px;"><h2>🤖 AI Analysis</h2><p style="margin: 0;">${escapeHtml(analysis.explanation)}</p></div>` : ''}
      ${analysis.recommendedActions.length > 0 ? `<div class="section"><h2>Recommended Actions</h2><pre>${actionsList}</pre></div>` : ''}
      <div class="section">
        <h2>What to Do</h2>
        ${analysis.isPhishing ? '<p><strong>⚠️ Do NOT click any links or provide credentials.</strong></p>' : '<p>This email appears legitimate. However, always remain vigilant.</p>'}
      </div>
      <div class="footer">
        <p><strong>Phishing Agent</strong> | Analyzed at ${new Date(analysis.analysisTimestamp).toLocaleString()}</p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Build indicators list
 */
function buildIndicatorsList(analysis: PhishingAnalysisResult): string {
  return analysis.indicators
    .slice(0, 5)
    .map((ind) => `  • ${escapeHtml(ind.description)}`)
    .join('\n');
}

/**
 * Build actions list
 */
function buildActionsList(analysis: PhishingAnalysisResult): string {
  return analysis.recommendedActions
    .slice(0, 3)
    .map((action) => {
      const icon = action.priority === 'urgent' ? '🔴' : action.priority === 'high' ? '🟡' : '🟢';
      return `  ${icon} ${escapeHtml(action.description)}`;
    })
    .join('\n');
}

/**
 * Build error reply HTML
 */
export function buildErrorReplyHtml(processingId: string): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .error-box { background-color: #FFF3E0; border-left: 4px solid #FF9800; padding: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-box">
      <h2>⚠️ Analysis Error</h2>
      <p>We encountered an error while analyzing your email. The security team has been notified.</p>
      <p><strong>Processing ID:</strong> ${processingId}</p>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Create Graph API reply message structure
 */
export function createReplyMessage(
  originalEmail: any,
  htmlBody: string,
  isPhishing: boolean
): any {
  const subject = originalEmail.subject || '(No Subject)';
  const senderEmail = originalEmail.from?.emailAddress?.address;

  return {
    message: {
      subject: `Re: ${subject}`,
      body: { contentType: 'HTML', content: htmlBody },
      toRecipients: [{ emailAddress: { address: senderEmail } }],
      importance: isPhishing ? 'high' : 'normal',
    },
  };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Exported for tests
export const __testEscapeHtml = escapeHtml;
