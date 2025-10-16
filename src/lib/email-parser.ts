/**
 * Email Parser
 * Extracts and parses email headers from raw email text
 */

import { EmailHeaders } from './types.js';
import { securityLogger } from './logger.js';

export interface ParsedEmail {
  headers: EmailHeaders;
  body?: string;
  rawHeaders: Map<string, string[]>;
}

export class EmailParser {
  /**
   * Parse raw email text into structured format
   */
  static parseEmail(rawEmail: string): ParsedEmail {
    const lines = rawEmail.split(/\r?\n/);
    const headers: EmailHeaders = {
      'message-id': '',
      from: '',
      to: '',
      subject: '',
      date: '',
    };
    const rawHeaders = new Map<string, string[]>();
    let body = '';
    let inHeaders = true;
    let currentHeaderName = '';
    let currentHeaderValue = '';

    for (const line of lines) {
      // Detect end of headers (blank line)
      if (inHeaders && line.trim() === '') {
        // Flush last header
        if (currentHeaderName) {
          this.addHeader(rawHeaders, currentHeaderName, currentHeaderValue.trim());
        }
        inHeaders = false;
        continue;
      }

      if (inHeaders) {
        // Check if this is a continuation line (starts with whitespace)
        if (line.match(/^\s/) && currentHeaderName) {
          currentHeaderValue += ' ' + line.trim();
        } else {
          // New header line
          // First, save previous header if exists
          if (currentHeaderName) {
            this.addHeader(rawHeaders, currentHeaderName, currentHeaderValue.trim());
          }

          // Parse new header
          const match = line.match(/^([^:]+):\s*(.*)$/);
          if (match) {
            currentHeaderName = match[1].toLowerCase();
            currentHeaderValue = match[2];
          }
        }
      } else {
        // Body content
        body += line + '\n';
      }
    }

    // Extract standard headers
    headers['message-id'] = this.getHeader(rawHeaders, 'message-id') || `generated-${Date.now()}@parser`;
    headers.from = this.getHeader(rawHeaders, 'from') || '';
    headers.to = this.getHeader(rawHeaders, 'to') || '';
    headers.subject = this.getHeader(rawHeaders, 'subject') || '';
    headers.date = this.getHeader(rawHeaders, 'date') || new Date().toISOString();

    // Extract authentication headers (only if they exist)
    const receivedSpf = this.getHeader(rawHeaders, 'received-spf');
    if (receivedSpf) headers['received-spf'] = receivedSpf;

    const authResults = this.getHeader(rawHeaders, 'authentication-results');
    if (authResults) headers['authentication-results'] = authResults;

    const dmarcResults = this.getHeader(rawHeaders, 'dmarc-results');
    if (dmarcResults) headers['dmarc-results'] = dmarcResults;

    const originatingIp = this.getHeader(rawHeaders, 'x-originating-ip');
    if (originatingIp) headers['x-originating-ip'] = originatingIp;

    const replyTo = this.getHeader(rawHeaders, 'reply-to');
    if (replyTo) headers['reply-to'] = replyTo;

    const received = this.getHeader(rawHeaders, 'received');
    if (received) headers.received = received;

    // Add any other headers that exist
    for (const [key, values] of rawHeaders.entries()) {
      if (!headers[key]) {
        headers[key] = values[0];
      }
    }

    securityLogger.debug('Email parsed successfully', {
      messageId: headers['message-id'],
      from: headers.from,
      subject: headers.subject,
      headerCount: rawHeaders.size,
    });

    const trimmedBody = body.trim();
    const result: ParsedEmail = {
      headers,
      rawHeaders,
    };

    // Only add body if it exists
    if (trimmedBody) {
      result.body = trimmedBody;
    }

    return result;
  }

  /**
   * Extract email address from "Name <email@domain.com>" format
   */
  static extractEmailAddress(headerValue: string): string {
    const match = headerValue.match(/<([^>]+)>/);
    if (match) {
      return match[1];
    }
    // If no angle brackets, assume the whole value is an email
    return headerValue.trim();
  }

  /**
   * Extract domain from email address
   */
  static extractDomain(email: string): string {
    const address = this.extractEmailAddress(email);
    const match = address.match(/@(.+)$/);
    return match ? match[1] : '';
  }

  /**
   * Extract display name from "Name <email@domain.com>" format
   */
  static extractDisplayName(headerValue: string): string {
    const match = headerValue.match(/^([^<]+)</);
    if (match) {
      return match[1].trim().replace(/^["']|["']$/g, '');
    }
    return '';
  }

  /**
   * Helper to add header to raw headers map
   */
  private static addHeader(map: Map<string, string[]>, name: string, value: string): void {
    const key = name.toLowerCase();
    const existing = map.get(key) || [];
    existing.push(value);
    map.set(key, existing);
  }

  /**
   * Helper to get first header value
   */
  private static getHeader(map: Map<string, string[]>, name: string): string | undefined {
    const values = map.get(name.toLowerCase());
    return values && values.length > 0 ? values[0] : undefined;
  }
}
