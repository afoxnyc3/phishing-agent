import { PhishingAnalysisResult } from '../lib/types.js';

export interface DailyMetrics {
  date: string;
  totalAnalyzed: number;
  phishingDetected: number;
  legitimateEmails: number;
  detectionRate: number;
  severityBreakdown: { low: number; medium: number; high: number; critical: number };
  avgRiskScore: number;
  avgConfidence: number;
}

export interface SenderStats {
  sender: string;
  domain: string;
  totalEmails: number;
  phishingEmails: number;
  avgRiskScore: number;
  lastSeen: Date;
}

export interface DashboardReport {
  generatedAt: Date;
  period: { start: Date; end: Date };
  summary: {
    totalAnalyzed: number;
    phishingDetected: number;
    legitimateEmails: number;
    detectionRate: number;
    avgRiskScore: number;
  };
  dailyMetrics: DailyMetrics[];
  topPhishingSenders: SenderStats[];
  topPhishingDomains: { domain: string; count: number; avgRiskScore: number }[];
  severityDistribution: { low: number; medium: number; high: number; critical: number };
  indicatorBreakdown: { type: string; count: number; avgConfidence: number }[];
}

export interface StoredResult {
  result: PhishingAnalysisResult;
  sender: string;
  domain: string;
  timestamp: Date;
}
