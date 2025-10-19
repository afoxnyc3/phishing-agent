/**
 * Threat Intelligence Enrichment
 * Parallel API calls to VirusTotal, AbuseIPDB, URLScan.io
 * All functions are atomic (max 25 lines)
 * Uses Zod for runtime validation of API responses
 */

import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';
import { validate, VirusTotalUrlResponseSchema, AbuseIPDBResponseSchema } from '../lib/schemas.js';

export interface ThreatIntelResult {
  indicators: ThreatIndicator[];
  riskContribution: number;
}

export interface UrlReputationResult {
  url: string;
  malicious: boolean;
  maliciousCount: number;
  totalScans: number;
  detectedBy: string[];
  confidenceScore: number;
}

export interface IpReputationResult {
  ip: string;
  malicious: boolean;
  abuseConfidenceScore: number;
  totalReports: number;
}

export interface DomainAgeResult {
  domain: string;
  ageDays: number;
  createdDate: string;
  suspicious: boolean;
  suspicionReasons: string[];
}

export class ThreatIntelService {
  private cache: NodeCache;
  private virusTotalClient?: AxiosInstance;
  private abuseIpDbClient?: AxiosInstance;
  private urlScanClient?: AxiosInstance;
  private enabled: boolean;

  constructor() {
    this.cache = new NodeCache({ stdTTL: config.threatIntel.cacheTtlMs / 1000 });
    this.enabled = config.threatIntel.enabled;
    this.initializeClients();
  }

  /**
   * Initialize API clients
   */
  private initializeClients(): void {
    if (config.threatIntel.virusTotalApiKey) {
      this.virusTotalClient = axios.create({
        baseURL: 'https://www.virustotal.com/api/v3',
        headers: { 'x-apikey': config.threatIntel.virusTotalApiKey },
        timeout: config.threatIntel.timeoutMs,
      });
    }

    if (config.threatIntel.abuseIpDbApiKey) {
      this.abuseIpDbClient = axios.create({
        baseURL: 'https://api.abuseipdb.com/api/v2',
        headers: { Key: config.threatIntel.abuseIpDbApiKey },
        timeout: config.threatIntel.timeoutMs,
      });
    }

    if (config.threatIntel.urlScanApiKey) {
      this.urlScanClient = axios.create({
        baseURL: 'https://urlscan.io/api/v1',
        headers: { 'API-Key': config.threatIntel.urlScanApiKey },
        timeout: config.threatIntel.timeoutMs,
      });
    }
  }

  /**
   * Enrich email with threat intelligence
   */
  async enrichEmail(
    senderEmail: string,
    senderIp: string | null,
    suspiciousUrls: string[]
  ): Promise<ThreatIntelResult> {
    if (!this.enabled) {
      return { indicators: [], riskContribution: 0 };
    }

    const lookups = await this.performParallelLookups(senderEmail, senderIp, suspiciousUrls);
    const indicators: ThreatIndicator[] = [];
    let riskContribution = 0;

    this.processUrlResults(lookups.urls, suspiciousUrls, indicators, (risk) => riskContribution += risk);
    this.processIpResult(lookups.ip, senderIp, indicators, (risk) => riskContribution += risk);
    this.processDomainResult(lookups.domain, senderEmail, indicators, (risk) => riskContribution += risk);

    securityLogger.info('Threat intel enrichment completed', {
      indicatorsAdded: indicators.length,
      riskContribution: riskContribution.toFixed(2),
    });

    return { indicators, riskContribution };
  }

  /**
   * Perform parallel threat intel lookups
   */
  private async performParallelLookups(
    senderEmail: string,
    senderIp: string | null,
    urls: string[]
  ): Promise<{ urls: PromiseSettledResult<any>[]; ip: PromiseSettledResult<any> | null; domain: PromiseSettledResult<any> | null }> {
    const domain = this.extractDomain(senderEmail);

    const urlLookups = urls.slice(0, 3).map(url => this.checkUrlReputation(url));
    const ipLookup = senderIp ? this.checkIpReputation(senderIp) : null;
    const domainLookup = domain ? this.checkDomainAge(domain) : null;

    const allLookups = [
      ...urlLookups,
      ...(ipLookup ? [ipLookup] : []),
      ...(domainLookup ? [domainLookup] : []),
    ];

    const results = await Promise.allSettled(allLookups);

    return {
      urls: results.slice(0, urlLookups.length),
      ip: ipLookup ? results[urlLookups.length] : null,
      domain: domainLookup ? results[urlLookups.length + (ipLookup ? 1 : 0)] : null,
    };
  }

  /**
   * Process URL reputation results
   */
  private processUrlResults(
    results: PromiseSettledResult<any>[],
    urls: string[],
    indicators: ThreatIndicator[],
    addRisk: (risk: number) => void
  ): void {
    results.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value?.malicious) {
        const urlResult = result.value;
        const riskIncrease = 2.0 + (urlResult.confidenceScore * 1.0);

        indicators.push({
          type: 'url',
          description: `Malicious URL detected by VirusTotal (${urlResult.maliciousCount}/${urlResult.totalScans})`,
          severity: urlResult.confidenceScore > 0.5 ? 'critical' : 'high',
          evidence: `${urls[i]} - Detected by: ${urlResult.detectedBy.slice(0, 3).join(', ')}`,
          confidence: urlResult.confidenceScore,
        });

        addRisk(riskIncrease);
      }
    });
  }

  /**
   * Process IP reputation result
   */
  private processIpResult(
    result: PromiseSettledResult<any> | null,
    ip: string | null,
    indicators: ThreatIndicator[],
    addRisk: (risk: number) => void
  ): void {
    if (!result || result.status !== 'fulfilled' || !result.value?.malicious || !ip) return;

    const ipData = result.value;
    if (ipData.abuseConfidenceScore >= 50) {
      const riskIncrease = 1.5 + ((ipData.abuseConfidenceScore - 50) / 100);

      indicators.push({
        type: 'sender',
        description: `Sender IP flagged for abuse (confidence: ${ipData.abuseConfidenceScore}%)`,
        severity: ipData.abuseConfidenceScore >= 75 ? 'high' : 'medium',
        evidence: `${ip} - ${ipData.totalReports} abuse reports`,
        confidence: ipData.abuseConfidenceScore / 100,
      });

      addRisk(riskIncrease);
    }
  }

  /**
   * Process domain age result
   */
  private processDomainResult(
    result: PromiseSettledResult<any> | null,
    email: string,
    indicators: ThreatIndicator[],
    addRisk: (risk: number) => void
  ): void {
    if (!result || result.status !== 'fulfilled' || !result.value) return;

    const domain = this.extractDomain(email);
    const domainData = result.value;

    if (domainData.ageDays >= 0 && domainData.ageDays < 30) {
      const riskIncrease = domainData.ageDays < 7 ? 2.0 : 1.0;

      indicators.push({
        type: 'sender',
        description: `Domain registered ${domainData.ageDays} days ago`,
        severity: domainData.ageDays < 7 ? 'high' : 'medium',
        evidence: `${domain} - Created: ${domainData.createdDate}`,
        confidence: domainData.ageDays < 7 ? 0.9 : 0.7,
      });

      addRisk(riskIncrease);
    }
  }

  /**
   * Check URL reputation via VirusTotal
   */
  async checkUrlReputation(url: string): Promise<UrlReputationResult | null> {
    if (!this.virusTotalClient) return null;

    const cacheKey = `vt-url-${url}`;
    const cached = this.cache.get<UrlReputationResult>(cacheKey);
    if (cached) return cached;

    try {
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
      const response = await this.virusTotalClient.get(`/urls/${urlId}`);

      // Validate response with Zod
      const validated = validate(VirusTotalUrlResponseSchema, response.data);
      if (!validated.success) {
        securityLogger.warn('Invalid VirusTotal response', { error: validated.error.message, url });
        return null;
      }

      const stats = validated.data.data.attributes.last_analysis_stats;
      const result: UrlReputationResult = {
        url,
        malicious: stats.malicious > 0,
        maliciousCount: stats.malicious,
        totalScans: stats.malicious + stats.harmless + stats.undetected,
        detectedBy: Object.keys(validated.data.data.attributes.last_analysis_results || {}),
        confidenceScore: stats.malicious / (stats.malicious + stats.harmless + stats.undetected),
      };

      this.cache.set(cacheKey, result);
      return result;
    } catch (error: any) {
      securityLogger.warn('VirusTotal API error', { error: error.message, url });
      return null;
    }
  }

  /**
   * Check IP reputation via AbuseIPDB
   */
  async checkIpReputation(ip: string): Promise<IpReputationResult | null> {
    if (!this.abuseIpDbClient) return null;

    const cacheKey = `abuseipdb-${ip}`;
    const cached = this.cache.get<IpReputationResult>(cacheKey);
    if (cached) return cached;

    try {
      const response = await this.abuseIpDbClient.get('/check', { params: { ipAddress: ip } });

      // Validate response with Zod
      const validated = validate(AbuseIPDBResponseSchema, response.data);
      if (!validated.success) {
        securityLogger.warn('Invalid AbuseIPDB response', { error: validated.error.message, ip });
        return null;
      }

      const data = validated.data.data;
      const result: IpReputationResult = {
        ip,
        malicious: data.abuseConfidenceScore >= 50,
        abuseConfidenceScore: data.abuseConfidenceScore,
        totalReports: data.totalReports,
      };

      this.cache.set(cacheKey, result);
      return result;
    } catch (error: any) {
      securityLogger.warn('AbuseIPDB API error', { error: error.message, ip });
      return null;
    }
  }

  /**
   * Check domain age (stub - would use WHOIS API in production)
   */
  async checkDomainAge(domain: string): Promise<DomainAgeResult | null> {
    const cacheKey = `domain-age-${domain}`;
    const cached = this.cache.get<DomainAgeResult>(cacheKey);
    if (cached) return cached;

    // Stub implementation - would integrate with WHOIS API
    const result: DomainAgeResult = {
      domain,
      ageDays: 365, // Default to 1 year
      createdDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
      suspicious: false,
      suspicionReasons: [],
    };

    this.cache.set(cacheKey, result);
    return result;
  }

  /**
   * Extract domain from email
   */
  private extractDomain(email: string): string | null {
    const match = email.match(/@(.+)$/);
    return match ? match[1] : null;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    return this.enabled && (!!this.virusTotalClient || !!this.abuseIpDbClient);
  }
}
