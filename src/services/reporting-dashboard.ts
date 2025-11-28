import { PhishingAnalysisResult } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';

export interface DailyMetrics {
  date: string; totalAnalyzed: number; phishingDetected: number; legitimateEmails: number; detectionRate: number;
  severityBreakdown: { low: number; medium: number; high: number; critical: number }; avgRiskScore: number; avgConfidence: number;
}

export interface SenderStats {
  sender: string; domain: string; totalEmails: number; phishingEmails: number; avgRiskScore: number; lastSeen: Date;
}

export interface DashboardReport {
  generatedAt: Date; period: { start: Date; end: Date };
  summary: { totalAnalyzed: number; phishingDetected: number; legitimateEmails: number; detectionRate: number; avgRiskScore: number };
  dailyMetrics: DailyMetrics[]; topPhishingSenders: SenderStats[];
  topPhishingDomains: { domain: string; count: number; avgRiskScore: number }[];
  severityDistribution: { low: number; medium: number; high: number; critical: number };
  indicatorBreakdown: { type: string; count: number; avgConfidence: number }[];
}

interface StoredResult { result: PhishingAnalysisResult; sender: string; domain: string; timestamp: Date; }

export class ReportingDashboardService {
  private results: StoredResult[] = [];
  private maxStoredResults: number;
  private retentionDays: number;

  constructor(options: { maxStoredResults?: number; retentionDays?: number } = {}) {
    this.maxStoredResults = options.maxStoredResults || 10000;
    this.retentionDays = options.retentionDays || 30;
  }

  recordAnalysis(result: PhishingAnalysisResult, sender: string): void {
    const domain = this.extractDomain(sender);
    this.results.push({ result, sender, domain, timestamp: new Date() });
    if (this.results.length > this.maxStoredResults) this.results.shift();
    this.cleanupOldResults();
  }

  generateReport(days: number = 7): DashboardReport {
    const end = new Date();
    const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
    const filtered = this.results.filter((r) => r.timestamp >= start && r.timestamp <= end);
    securityLogger.debug('Generating dashboard report', { days, resultsCount: filtered.length });

    return {
      generatedAt: new Date(),
      period: { start, end },
      summary: this.calculateSummary(filtered),
      dailyMetrics: this.calculateDailyMetrics(filtered, days),
      topPhishingSenders: this.getTopPhishingSenders(filtered, 10),
      topPhishingDomains: this.getTopPhishingDomains(filtered, 10),
      severityDistribution: this.calculateSeverityDistribution(filtered),
      indicatorBreakdown: this.calculateIndicatorBreakdown(filtered),
    };
  }

  getDailyMetrics(date: Date): DailyMetrics {
    const dateStr = date.toISOString().split('T')[0];
    const dayStart = new Date(dateStr);
    const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
    const dayResults = this.results.filter((r) => r.timestamp >= dayStart && r.timestamp < dayEnd);
    return this.createDailyMetrics(dateStr, dayResults);
  }

  getTopSenders(limit: number = 10): SenderStats[] {
    return this.getTopPhishingSenders(this.results, limit);
  }

  getSeverityTrend(days: number = 7): { date: string; critical: number; high: number; medium: number; low: number }[] {
    const trend: { date: string; critical: number; high: number; medium: number; low: number }[] = [];
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
      const metrics = this.getDailyMetrics(date);
      trend.push({ date: metrics.date, ...metrics.severityBreakdown });
    }
    return trend;
  }

  getResultCount(): number {
    return this.results.length;
  }

  reset(): void {
    this.results = [];
  }

  private extractDomain(sender: string): string {
    const match = sender.match(/@([^>]+)/);
    return match ? match[1].toLowerCase() : sender.toLowerCase();
  }

  private cleanupOldResults(): void {
    const cutoff = new Date(Date.now() - this.retentionDays * 24 * 60 * 60 * 1000);
    this.results = this.results.filter((r) => r.timestamp >= cutoff);
  }

  private calculateSummary(results: StoredResult[]): DashboardReport['summary'] {
    const total = results.length;
    const phishing = results.filter((r) => r.result.isPhishing).length;
    const legitimate = total - phishing;
    const avgRisk = total > 0 ? results.reduce((sum, r) => sum + r.result.riskScore, 0) / total : 0;
    return { totalAnalyzed: total, phishingDetected: phishing, legitimateEmails: legitimate, detectionRate: total > 0 ? phishing / total : 0, avgRiskScore: Math.round(avgRisk * 100) / 100 };
  }

  private calculateDailyMetrics(results: StoredResult[], days: number): DailyMetrics[] {
    const dailyMetrics: DailyMetrics[] = [];
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
      dailyMetrics.push(this.getDailyMetrics(date));
    }
    return dailyMetrics;
  }

  private createDailyMetrics(dateStr: string, results: StoredResult[]): DailyMetrics {
    const total = results.length;
    const phishing = results.filter((r) => r.result.isPhishing).length;
    const severityBreakdown = { low: 0, medium: 0, high: 0, critical: 0 };
    let riskSum = 0, confSum = 0;

    for (const r of results) {
      severityBreakdown[r.result.severity]++;
      riskSum += r.result.riskScore;
      confSum += r.result.confidence;
    }

    return {
      date: dateStr, totalAnalyzed: total, phishingDetected: phishing, legitimateEmails: total - phishing,
      detectionRate: total > 0 ? phishing / total : 0, severityBreakdown,
      avgRiskScore: total > 0 ? Math.round((riskSum / total) * 100) / 100 : 0,
      avgConfidence: total > 0 ? Math.round((confSum / total) * 100) / 100 : 0,
    };
  }

  private getTopPhishingSenders(results: StoredResult[], limit: number): SenderStats[] {
    const senderMap = new Map<string, { total: number; phishing: number; riskSum: number; lastSeen: Date; domain: string }>();

    for (const r of results) {
      const existing = senderMap.get(r.sender) || { total: 0, phishing: 0, riskSum: 0, lastSeen: r.timestamp, domain: r.domain };
      existing.total++;
      if (r.result.isPhishing) existing.phishing++;
      existing.riskSum += r.result.riskScore;
      if (r.timestamp > existing.lastSeen) existing.lastSeen = r.timestamp;
      senderMap.set(r.sender, existing);
    }

    return Array.from(senderMap.entries())
      .filter(([, stats]) => stats.phishing > 0)
      .map(([sender, stats]) => ({ sender, domain: stats.domain, totalEmails: stats.total, phishingEmails: stats.phishing, avgRiskScore: Math.round((stats.riskSum / stats.total) * 100) / 100, lastSeen: stats.lastSeen }))
      .sort((a, b) => b.phishingEmails - a.phishingEmails)
      .slice(0, limit);
  }

  private getTopPhishingDomains(results: StoredResult[], limit: number): { domain: string; count: number; avgRiskScore: number }[] {
    const domainMap = new Map<string, { count: number; riskSum: number }>();

    for (const r of results) {
      if (!r.result.isPhishing) continue;
      const existing = domainMap.get(r.domain) || { count: 0, riskSum: 0 };
      existing.count++;
      existing.riskSum += r.result.riskScore;
      domainMap.set(r.domain, existing);
    }

    return Array.from(domainMap.entries())
      .map(([domain, stats]) => ({ domain, count: stats.count, avgRiskScore: Math.round((stats.riskSum / stats.count) * 100) / 100 }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  private calculateSeverityDistribution(results: StoredResult[]): { low: number; medium: number; high: number; critical: number } {
    const dist = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const r of results) dist[r.result.severity]++;
    return dist;
  }

  private calculateIndicatorBreakdown(results: StoredResult[]): { type: string; count: number; avgConfidence: number }[] {
    const indicatorMap = new Map<string, { count: number; confSum: number }>();

    for (const r of results) {
      for (const ind of r.result.indicators) {
        const existing = indicatorMap.get(ind.type) || { count: 0, confSum: 0 };
        existing.count++;
        existing.confSum += ind.confidence;
        indicatorMap.set(ind.type, existing);
      }
    }

    return Array.from(indicatorMap.entries())
      .map(([type, stats]) => ({ type, count: stats.count, avgConfidence: Math.round((stats.confSum / stats.count) * 100) / 100 }))
      .sort((a, b) => b.count - a.count);
  }
}

export const reportingDashboard = new ReportingDashboardService();
