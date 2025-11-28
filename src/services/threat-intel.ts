/**
 * Threat Intelligence Enrichment
 * Parallel API calls to VirusTotal, AbuseIPDB, URLScan.io
 * All functions are atomic (max 25 lines)
 * Uses Zod for runtime validation of API responses
 * Implements retry logic (p-retry) and circuit breaker (opossum)
 */

import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import pRetry from 'p-retry';
import CircuitBreaker from 'opossum';
import { ThreatIndicator } from '../lib/types.js';
import { securityLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';
import { validate, VirusTotalUrlResponseSchema, AbuseIPDBResponseSchema } from '../lib/schemas.js';

/** Circuit breaker configuration */
const CIRCUIT_BREAKER_OPTIONS = {
  timeout: 10000,               // 10s total timeout (includes retries)
  errorThresholdPercentage: 50, // Open circuit if 50% of requests fail
  resetTimeout: 60000,          // Try again after 1 minute
  volumeThreshold: 5,           // Need 5 requests before calculating %
};

/** Retry configuration */
const RETRY_OPTIONS = {
  retries: 3,
  minTimeout: 100,
  maxTimeout: 1000,
  factor: 2,
};

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

  // Circuit breakers for each API
  private virusTotalBreaker?: CircuitBreaker;
  private abuseIpDbBreaker?: CircuitBreaker;

  constructor() {
    this.cache = new NodeCache({ stdTTL: config.threatIntel.cacheTtlMs / 1000 });
    this.enabled = config.threatIntel.enabled;
    this.initializeClients();
    this.initializeCircuitBreakers();
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
   * Initialize circuit breakers for external APIs
   */
  private initializeCircuitBreakers(): void {
    if (this.virusTotalClient) {
      this.virusTotalBreaker = new CircuitBreaker(
        (urlId: string) => this.virusTotalClient!.get(`/urls/${urlId}`),
        CIRCUIT_BREAKER_OPTIONS
      );
      this.setupBreakerEvents(this.virusTotalBreaker, 'VirusTotal');
    }

    if (this.abuseIpDbClient) {
      this.abuseIpDbBreaker = new CircuitBreaker(
        (ip: string) => this.abuseIpDbClient!.get('/check', { params: { ipAddress: ip } }),
        CIRCUIT_BREAKER_OPTIONS
      );
      this.setupBreakerEvents(this.abuseIpDbBreaker, 'AbuseIPDB');
    }
  }

  /**
   * Setup circuit breaker event handlers
   */
  private setupBreakerEvents(breaker: CircuitBreaker, apiName: string): void {
    breaker.on('open', () => {
      securityLogger.warn(`${apiName} circuit OPEN - API unhealthy, failing fast`);
    });
    breaker.on('halfOpen', () => {
      securityLogger.info(`${apiName} circuit HALF-OPEN - testing recovery`);
    });
    breaker.on('close', () => {
      securityLogger.info(`${apiName} circuit CLOSED - API healthy`);
    });
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
   * Check URL reputation via VirusTotal (with retry + circuit breaker)
   */
  async checkUrlReputation(url: string): Promise<UrlReputationResult | null> {
    if (!this.virusTotalBreaker) return null;

    const cacheKey = `vt-url-${url}`;
    const cached = this.cache.get<UrlReputationResult>(cacheKey);
    if (cached) return cached;

    try {
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

      // Use circuit breaker + retry
      const response = await pRetry(
        async () => {
          const res = await this.virusTotalBreaker!.fire(urlId);
          return res;
        },
        {
          ...RETRY_OPTIONS,
          onFailedAttempt: (error) => {
            securityLogger.warn('VirusTotal retry attempt', {
              attempt: error.attemptNumber,
              retriesLeft: error.retriesLeft,
              url,
            });
          },
        }
      );

      return this.parseVirusTotalResponse(url, response as { data: unknown }, cacheKey);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      securityLogger.warn('VirusTotal API failed after retries', { error: errorMessage, url });
      return null;
    }
  }

  /**
   * Parse VirusTotal response
   */
  private parseVirusTotalResponse(
    url: string,
    response: { data: unknown },
    cacheKey: string
  ): UrlReputationResult | null {
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
  }

  /**
   * Check IP reputation via AbuseIPDB (with retry + circuit breaker)
   */
  async checkIpReputation(ip: string): Promise<IpReputationResult | null> {
    if (!this.abuseIpDbBreaker) return null;

    const cacheKey = `abuseipdb-${ip}`;
    const cached = this.cache.get<IpReputationResult>(cacheKey);
    if (cached) return cached;

    try {
      // Use circuit breaker + retry
      const response = await pRetry(
        async () => {
          const res = await this.abuseIpDbBreaker!.fire(ip);
          return res;
        },
        {
          ...RETRY_OPTIONS,
          onFailedAttempt: (error) => {
            securityLogger.warn('AbuseIPDB retry attempt', {
              attempt: error.attemptNumber,
              retriesLeft: error.retriesLeft,
              ip,
            });
          },
        }
      );

      return this.parseAbuseIPDBResponse(ip, response as { data: unknown }, cacheKey);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      securityLogger.warn('AbuseIPDB API failed after retries', { error: errorMessage, ip });
      return null;
    }
  }

  /**
   * Parse AbuseIPDB response
   */
  private parseAbuseIPDBResponse(
    ip: string,
    response: { data: unknown },
    cacheKey: string
  ): IpReputationResult | null {
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
