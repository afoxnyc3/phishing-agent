/**
 * Microsoft Graph Email Parser
 * Converts Graph API email objects to EmailAnalysisRequest
 * All functions are atomic (max 25 lines)
 */

import { EmailAnalysisRequest } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';

/**
 * Parse Graph API email to analysis request
 */
export function parseGraphEmail(graphEmail: any): EmailAnalysisRequest {
  const sender = graphEmail.from?.emailAddress?.address || 'unknown@unknown.com';
  const recipient = graphEmail.toRecipients?.[0]?.emailAddress?.address || 'unknown@unknown.com';
  const subject = graphEmail.subject || '(No Subject)';
  const messageId = graphEmail.internetMessageId || graphEmail.id;
  const timestamp = new Date(graphEmail.receivedDateTime || graphEmail.sentDateTime || Date.now());

  const headers = extractHeaders(graphEmail, sender, recipient, subject, messageId, timestamp);
  const body = graphEmail.body?.content || graphEmail.bodyPreview || '';
  const attachments = extractAttachments(graphEmail);

  securityLogger.debug('Parsed Graph email', {
    sender, subject, messageId,
    headerCount: Object.keys(headers).length,
    attachmentCount: attachments.length,
  });

  return { sender, recipient, subject, messageId, timestamp, headers, body, attachments };
}

/**
 * Extract headers from Graph email
 */
function extractHeaders(
  graphEmail: any,
  sender: string,
  recipient: string,
  subject: string,
  messageId: string,
  timestamp: Date
): any {
  const headers: any = {
    'message-id': messageId,
    from: sender,
    to: recipient,
    subject,
    date: timestamp.toISOString(),
  };

  // Extract internet message headers
  if (graphEmail.internetMessageHeaders && Array.isArray(graphEmail.internetMessageHeaders)) {
    for (const header of graphEmail.internetMessageHeaders) {
      if (header.name && header.value) {
        headers[header.name.toLowerCase()] = header.value;
      }
    }
  }

  return headers;
}

/**
 * Extract attachments from Graph email
 */
function extractAttachments(graphEmail: any): any[] {
  if (!graphEmail.attachments || !Array.isArray(graphEmail.attachments)) {
    return [];
  }

  return graphEmail.attachments.map((att: any) => ({
    filename: att.name || 'unknown',
    contentType: att.contentType || 'application/octet-stream',
    size: att.size || 0,
  }));
}

/**
 * Validate analysis request
 */
export function validateAnalysisRequest(request: EmailAnalysisRequest): boolean {
  if (!request.sender || !request.sender.includes('@')) {
    securityLogger.warn('Invalid sender email', { sender: request.sender });
    return false;
  }

  if (!request.messageId) {
    securityLogger.warn('Missing message ID');
    return false;
  }

  if (!request.headers || Object.keys(request.headers).length === 0) {
    securityLogger.warn('Missing email headers');
    return false;
  }

  return true;
}
