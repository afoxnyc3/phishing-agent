/**
 * Type definitions for phishing agent
 * Simplified for email analysis only
 */

// Email analysis request
export interface EmailAnalysisRequest {
  messageId: string;
  subject: string;
  sender: string;
  recipient: string;
  timestamp: Date;
  headers: EmailHeaders;
  body?: string;
  attachments?: EmailAttachment[];
}

// Email headers
export interface EmailHeaders {
  'message-id': string;
  from: string;
  to: string;
  subject: string;
  date: string;
  'received-spf'?: string;
  'authentication-results'?: string;
  'dmarc-results'?: string;
  'x-originating-ip'?: string;
  'reply-to'?: string;
  received?: string;
  [key: string]: string | undefined;
}

// Email attachments
export interface EmailAttachment {
  filename: string;
  contentType: string;
  size: number;
  hash?: string;
}

// Phishing analysis result
export interface PhishingAnalysisResult {
  messageId: string;
  isPhishing: boolean;
  confidence: number;
  riskScore: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  indicators: ThreatIndicator[];
  recommendedActions: RecommendedAction[];
  analysisTimestamp: Date;
  analysisId: string;
  /** AI-generated natural language explanation of the threat (optional) */
  explanation?: string;
}

// Threat indicator
export interface ThreatIndicator {
  type: 'header' | 'content' | 'url' | 'attachment' | 'sender' | 'behavioral';
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  evidence: string;
  confidence: number;
}

// Recommended action
export interface RecommendedAction {
  priority: 'low' | 'medium' | 'high' | 'urgent';
  action: string;
  description: string;
  automated: boolean;
  requiresApproval: boolean;
}

// Performance metrics
export interface PerformanceMetrics {
  timestamp: Date;
  operation: string;
  duration: number;
  success: boolean;
  errorMessage?: string;
}
