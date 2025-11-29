/**
 * Threat Intelligence Enrichment Service
 * Orchestrates parallel API calls to threat intel providers
 */

import NodeCache from 'node-cache';
import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';
import { VirusTotalClient, AbuseIPDBClient, UrlReputationResult, IpReputationResult } from './threat-intel-clients.js';

export { UrlReputationResult, IpReputationResult } from './threat-intel-clients.js';

export interface ThreatIntelResult {
  indicators: ThreatIndicator[];
  riskContribution: number;
}

export interface DomainAgeResult {
  domain: string;
  ageDays: number;
  createdDate: string;
  suspicious: boolean;
  suspicionReasons: string[];
}

/** Lookup results with proper types */
interface LookupResults {
  urls: PromiseSettledResult<UrlReputationResult | null>[];
  ip: PromiseSettledResult<IpReputationResult | null> | null;
  domain: PromiseSettledResult<DomainAgeResult | null> | null;
}

export class ThreatIntelService {
  private cache: NodeCache;
  private virusTotalClient?: VirusTotalClient;
  private abuseIpDbClient?: AbuseIPDBClient;
  private enabled: boolean;

  constructor() {
    this.cache = new NodeCache({ stdTTL: config.threatIntel.cacheTtlMs / 1000 });
    this.enabled = config.threatIntel.enabled;
    this.initializeClients();
  }

  private initializeClients(): void {
    if (config.threatIntel.virusTotalApiKey) {
      this.virusTotalClient = new VirusTotalClient(config.threatIntel.virusTotalApiKey, this.cache);
    }
    if (config.threatIntel.abuseIpDbApiKey) {
      this.abuseIpDbClient = new AbuseIPDBClient(config.threatIntel.abuseIpDbApiKey, this.cache);
    }
  }

  /** Enrich email with threat intelligence */
  async enrichEmail(senderEmail: string, senderIp: string | null, suspiciousUrls: string[]): Promise<ThreatIntelResult> {
    if (!this.enabled) return { indicators: [], riskContribution: 0 };

    const lookups = await this.performParallelLookups(senderEmail, senderIp, suspiciousUrls);
    const indicators: ThreatIndicator[] = [];
    let riskContribution = 0;

    this.processUrlResults(lookups.urls, suspiciousUrls, indicators, (r) => (riskContribution += r));
    this.processIpResult(lookups.ip, senderIp, indicators, (r) => (riskContribution += r));
    this.processDomainResult(lookups.domain, senderEmail, indicators, (r) => (riskContribution += r));

    securityLogger.info('Threat intel enrichment completed', {
      indicatorsAdded: indicators.length,
      riskContribution: riskContribution.toFixed(2),
    });

    return { indicators, riskContribution };
  }

  /** Perform parallel threat intel lookups */
  private async performParallelLookups(email: string, ip: string | null, urls: string[]): Promise<LookupResults> {
    const domain = this.extractDomain(email);
    const urlLookups = urls.slice(0, 3).map((u) => this.checkUrlReputation(u));
    const ipLookup = ip ? this.checkIpReputation(ip) : null;
    const domainLookup = domain ? this.checkDomainAge(domain) : null;

    const allLookups = [...urlLookups, ...(ipLookup ? [ipLookup] : []), ...(domainLookup ? [domainLookup] : [])];
    const results = await Promise.allSettled(allLookups);

    return {
      urls: results.slice(0, urlLookups.length) as PromiseSettledResult<UrlReputationResult | null>[],
      ip: ipLookup ? (results[urlLookups.length] as PromiseSettledResult<IpReputationResult | null>) : null,
      domain: domainLookup
        ? (results[urlLookups.length + (ipLookup ? 1 : 0)] as PromiseSettledResult<DomainAgeResult | null>)
        : null,
    };
  }

  /** Process URL reputation results */
  private processUrlResults(
    results: PromiseSettledResult<UrlReputationResult | null>[],
    urls: string[],
    indicators: ThreatIndicator[],
    addRisk: (risk: number) => void
  ): void {
    results.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value?.malicious) {
        const r = result.value;
        indicators.push({
          type: 'url',
          description: `Malicious URL detected by VirusTotal (${r.maliciousCount}/${r.totalScans})`,
          severity: r.confidenceScore > 0.5 ? 'critical' : 'high',
          evidence: `${urls[i]} - Detected by: ${r.detectedBy.slice(0, 3).join(', ')}`,
          confidence: r.confidenceScore,
        });
        addRisk(2.0 + r.confidenceScore);
      }
    });
  }

  /** Process IP reputation result */
  private processIpResult(
    result: PromiseSettledResult<IpReputationResult | null> | null,
    ip: string | null,
    indicators: ThreatIndicator[],
    addRisk: (risk: number) => void
  ): void {
    if (!result || result.status !== 'fulfilled' || !result.value?.malicious || !ip) return;
    const r = result.value;
    if (r.abuseConfidenceScore >= 50) {
      indicators.push({
        type: 'sender',
        description: `Sender IP flagged for abuse (confidence: ${r.abuseConfidenceScore}%)`,
        severity: r.abuseConfidenceScore >= 75 ? 'high' : 'medium',
        evidence: `${ip} - ${r.totalReports} abuse reports`,
        confidence: r.abuseConfidenceScore / 100,
      });
      addRisk(1.5 + (r.abuseConfidenceScore - 50) / 100);
    }
  }

  /** Process domain age result */
  private processDomainResult(
    result: PromiseSettledResult<DomainAgeResult | null> | null,
    email: string,
    indicators: ThreatIndicator[],
    addRisk: (risk: number) => void
  ): void {
    if (!result || result.status !== 'fulfilled' || !result.value) return;
    const domain = this.extractDomain(email);
    const r = result.value;
    if (r.ageDays >= 0 && r.ageDays < 30) {
      indicators.push({
        type: 'sender',
        description: `Domain registered ${r.ageDays} days ago`,
        severity: r.ageDays < 7 ? 'high' : 'medium',
        evidence: `${domain} - Created: ${r.createdDate}`,
        confidence: r.ageDays < 7 ? 0.9 : 0.7,
      });
      addRisk(r.ageDays < 7 ? 2.0 : 1.0);
    }
  }

  /** Check URL reputation via VirusTotal */
  async checkUrlReputation(url: string): Promise<UrlReputationResult | null> {
    return this.virusTotalClient?.checkUrl(url) ?? null;
  }

  /** Check IP reputation via AbuseIPDB */
  async checkIpReputation(ip: string): Promise<IpReputationResult | null> {
    return this.abuseIpDbClient?.checkIp(ip) ?? null;
  }

  /** Check domain age (stub - would use WHOIS API) */
  async checkDomainAge(domain: string): Promise<DomainAgeResult | null> {
    const cacheKey = `domain-age-${domain}`;
    const cached = this.cache.get<DomainAgeResult>(cacheKey);
    if (cached) return cached;

    const result: DomainAgeResult = {
      domain,
      ageDays: 365,
      createdDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
      suspicious: false,
      suspicionReasons: [],
    };
    this.cache.set(cacheKey, result);
    return result;
  }

  private extractDomain(email: string): string | null {
    const match = email.match(/@(.+)$/);
    return match ? match[1] : null;
  }

  async healthCheck(): Promise<boolean> {
    return this.enabled && (!!this.virusTotalClient || !!this.abuseIpDbClient);
  }
}
