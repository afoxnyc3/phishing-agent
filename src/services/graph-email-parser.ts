/**
 * Microsoft Graph Email Parser
 * Converts Graph API email objects to EmailAnalysisRequest
 * All functions are atomic (max 25 lines)
 * Uses Zod for runtime validation of Graph API responses
 */

import { EmailAnalysisRequest, EmailHeaders, EmailAttachment } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import {
  GraphEmail,
  GraphEmailSchema,
  GraphEmailListResponseSchema,
  GraphAttachment,
  safeParse,
} from '../lib/schemas.js';

/**
 * Parse Graph API email to analysis request
 * Validates input with Zod before processing
 */
export function parseGraphEmail(graphEmail: unknown): EmailAnalysisRequest {
  // Validate Graph email structure
  const validatedEmail = safeParse(GraphEmailSchema, graphEmail, 'Graph API email');

  const sender = validatedEmail.from?.emailAddress?.address || 'unknown@unknown.com';
  const recipient = validatedEmail.toRecipients?.[0]?.emailAddress?.address || 'unknown@unknown.com';
  const subject = validatedEmail.subject || '(No Subject)';
  const messageId = validatedEmail.internetMessageId || validatedEmail.id;
  const timestamp = new Date(validatedEmail.receivedDateTime || validatedEmail.sentDateTime || Date.now());

  const headers = extractHeaders(validatedEmail, sender, recipient, subject, messageId, timestamp);
  const body = validatedEmail.body?.content || validatedEmail.bodyPreview || '';
  const attachments = extractAttachments(validatedEmail);

  securityLogger.debug('Parsed Graph email', {
    sender,
    subject,
    messageId,
    headerCount: Object.keys(headers).length,
    attachmentCount: attachments.length,
  });

  return { sender, recipient, subject, messageId, timestamp, headers, body, attachments };
}

/**
 * Extract headers from Graph email
 */
function extractHeaders(
  graphEmail: GraphEmail,
  sender: string,
  recipient: string,
  subject: string,
  messageId: string,
  timestamp: Date
): EmailHeaders {
  const headers: EmailHeaders = {
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
function extractAttachments(graphEmail: GraphEmail): EmailAttachment[] {
  if (!graphEmail.attachments || !Array.isArray(graphEmail.attachments)) {
    return [];
  }

  return graphEmail.attachments.map((att: GraphAttachment) => ({
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

/**
 * Validate Graph API email list response
 * Returns validated emails array
 */
export function validateGraphEmailListResponse(response: unknown): GraphEmail[] {
  const validated = safeParse(GraphEmailListResponseSchema, response, 'Graph API email list');
  return validated.value;
}
