/**
 * Email Fetcher Service
 * Handles fetching emails from Microsoft Graph API with pagination support.
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { securityLogger } from '../lib/logger.js';
import { GraphEmail, GraphEmailSchema, GraphEmailListResponse, safeParse } from '../lib/schemas.js';
import { validateGraphEmailListResponse } from './graph-email-parser.js';

const EMAIL_SELECT_FIELDS =
  'id,subject,from,toRecipients,receivedDateTime,sentDateTime,' +
  'internetMessageId,internetMessageHeaders,body,hasAttachments';

export interface EmailFetcherConfig {
  mailboxAddress: string;
  maxPages?: number;
}

/**
 * Fetch new emails from mailbox with pagination support
 * Handles @odata.nextLink for large result sets
 */
export async function fetchNewEmails(
  client: Client,
  config: EmailFetcherConfig,
  sinceDate: string
): Promise<GraphEmail[]> {
  const allEmails: GraphEmail[] = [];
  const maxPages = config.maxPages || 5;
  let pageCount = 0;
  let nextLink: string | undefined = undefined;

  do {
    const response = await fetchEmailPage(client, config.mailboxAddress, sinceDate, nextLink);
    const validatedEmails = validateGraphEmailListResponse(response);
    allEmails.push(...validatedEmails);
    nextLink = (response as GraphEmailListResponse)['@odata.nextLink'];
    pageCount++;
    if (nextLink) {
      securityLogger.debug('Fetching next page of emails', {
        pageCount,
        maxPages,
        emailsSoFar: allEmails.length,
      });
    }
  } while (nextLink && pageCount < maxPages);

  if (nextLink && pageCount >= maxPages) {
    securityLogger.warn('Pagination limit reached - some emails may not be fetched', {
      pageCount,
      maxPages,
      totalFetched: allEmails.length,
    });
  }
  return allEmails;
}

/**
 * Fetch a single email by ID from Graph API
 */
export async function fetchEmailById(client: Client, mailboxAddress: string, messageId: string): Promise<GraphEmail> {
  const response = await client
    .api(`/users/${mailboxAddress}/messages/${messageId}`)
    .select(EMAIL_SELECT_FIELDS)
    .expand('attachments($select=name,contentType,size)')
    .get();
  return safeParse(GraphEmailSchema, response, 'Graph email by ID');
}

async function fetchEmailPage(
  client: Client,
  mailboxAddress: string,
  sinceDate: string,
  nextLink?: string
): Promise<GraphEmailListResponse> {
  if (nextLink) {
    return client.api(nextLink).get();
  }
  return client
    .api(`/users/${mailboxAddress}/messages`)
    .filter(`receivedDateTime ge ${sinceDate}`)
    .orderby('receivedDateTime asc')
    .top(50)
    .select(EMAIL_SELECT_FIELDS)
    .expand('attachments($select=name,contentType,size)')
    .get();
}
