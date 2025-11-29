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
    const { rawHeaders, body } = this.parseHeaderSection(rawEmail.split(/\r?\n/));
    const headers = this.extractStandardHeaders(rawHeaders);
    this.copyRemainingHeaders(rawHeaders, headers);

    securityLogger.debug('Email parsed successfully', {
      messageId: headers['message-id'],
      from: headers.from,
      subject: headers.subject,
      headerCount: rawHeaders.size,
    });

    const result: ParsedEmail = { headers, rawHeaders };
    const trimmedBody = body.trim();
    if (trimmedBody) result.body = trimmedBody;
    return result;
  }

  /** Parse header section and separate body */
  private static parseHeaderSection(lines: string[]): { rawHeaders: Map<string, string[]>; body: string } {
    const rawHeaders = new Map<string, string[]>();
    let body = '';
    let inHeaders = true;
    let currentName = '';
    let currentValue = '';

    for (const line of lines) {
      if (inHeaders && line.trim() === '') {
        if (currentName) this.addHeader(rawHeaders, currentName, currentValue.trim());
        inHeaders = false;
        continue;
      }
      if (inHeaders) {
        ({ currentName, currentValue } = this.processHeaderLine(line, currentName, currentValue, rawHeaders));
      } else {
        body += line + '\n';
      }
    }
    return { rawHeaders, body };
  }

  /** Process a single header line */
  private static processHeaderLine(
    line: string, currentName: string, currentValue: string, rawHeaders: Map<string, string[]>
  ): { currentName: string; currentValue: string } {
    if (line.match(/^\s/) && currentName) {
      return { currentName, currentValue: currentValue + ' ' + line.trim() };
    }
    if (currentName) this.addHeader(rawHeaders, currentName, currentValue.trim());
    const match = line.match(/^([^:]+):\s*(.*)$/);
    return match ? { currentName: match[1].toLowerCase(), currentValue: match[2] } : { currentName: '', currentValue: '' };
  }

  /** Extract standard email headers from raw headers map */
  private static extractStandardHeaders(rawHeaders: Map<string, string[]>): EmailHeaders {
    const headers: EmailHeaders = {
      'message-id': this.getHeader(rawHeaders, 'message-id') || `generated-${Date.now()}@parser`,
      from: this.getHeader(rawHeaders, 'from') || '',
      to: this.getHeader(rawHeaders, 'to') || '',
      subject: this.getHeader(rawHeaders, 'subject') || '',
      date: this.getHeader(rawHeaders, 'date') || new Date().toISOString(),
    };
    this.copyOptionalHeader(rawHeaders, headers, 'received-spf');
    this.copyOptionalHeader(rawHeaders, headers, 'authentication-results');
    this.copyOptionalHeader(rawHeaders, headers, 'dmarc-results');
    this.copyOptionalHeader(rawHeaders, headers, 'x-originating-ip');
    this.copyOptionalHeader(rawHeaders, headers, 'reply-to');
    this.copyOptionalHeader(rawHeaders, headers, 'received');
    return headers;
  }

  /** Copy optional header if it exists */
  private static copyOptionalHeader(rawHeaders: Map<string, string[]>, headers: EmailHeaders, name: string): void {
    const value = this.getHeader(rawHeaders, name);
    if (value) headers[name] = value;
  }

  /** Copy remaining headers not already in headers object */
  private static copyRemainingHeaders(rawHeaders: Map<string, string[]>, headers: EmailHeaders): void {
    for (const [key, values] of rawHeaders.entries()) {
      if (!headers[key]) headers[key] = values[0];
    }
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
