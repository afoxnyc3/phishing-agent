/**
 * Threat Intel API Clients
 * VirusTotal and AbuseIPDB client implementations with retry + circuit breaker
 */

import axios, { AxiosInstance } from 'axios';
import pRetry from 'p-retry';
import CircuitBreaker from 'opossum';
import NodeCache from 'node-cache';
import { securityLogger } from '../lib/logger.js';
import { config } from '../lib/config.js';
import { validate, VirusTotalUrlResponseSchema, AbuseIPDBResponseSchema } from '../lib/schemas.js';
import { getErrorMessage } from '../lib/errors.js';

/** Circuit breaker configuration */
const CIRCUIT_BREAKER_OPTIONS = {
  timeout: 10000,
  errorThresholdPercentage: 50,
  resetTimeout: 60000,
  volumeThreshold: 5,
};

/** Retry configuration */
const RETRY_OPTIONS = { retries: 3, minTimeout: 100, maxTimeout: 1000, factor: 2 };

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

/** VirusTotal API client with retry and circuit breaker */
export class VirusTotalClient {
  private client: AxiosInstance;
  private breaker: CircuitBreaker;
  private cache: NodeCache;

  constructor(apiKey: string, cache: NodeCache) {
    this.cache = cache;
    this.client = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      headers: { 'x-apikey': apiKey },
      timeout: config.threatIntel.timeoutMs,
    });
    this.breaker = new CircuitBreaker((urlId: string) => this.client.get(`/urls/${urlId}`), CIRCUIT_BREAKER_OPTIONS);
    this.setupBreakerEvents('VirusTotal');
  }

  private setupBreakerEvents(apiName: string): void {
    this.breaker.on('open', () => securityLogger.warn(`${apiName} circuit OPEN`));
    this.breaker.on('halfOpen', () => securityLogger.info(`${apiName} circuit HALF-OPEN`));
    this.breaker.on('close', () => securityLogger.info(`${apiName} circuit CLOSED`));
  }

  async checkUrl(url: string): Promise<UrlReputationResult | null> {
    const cacheKey = `vt-url-${url}`;
    const cached = this.cache.get<UrlReputationResult>(cacheKey);
    if (cached) return cached;

    try {
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
      const response = await pRetry(() => this.breaker.fire(urlId) as Promise<{ data: unknown }>, {
        ...RETRY_OPTIONS,
        onFailedAttempt: (e) => securityLogger.warn('VT retry', { attempt: e.attemptNumber, url }),
      });
      return this.parseResponse(url, response, cacheKey);
    } catch (error: unknown) {
      securityLogger.warn('VirusTotal failed', {
        error: getErrorMessage(error),
        url,
      });
      return null;
    }
  }

  private parseResponse(url: string, response: { data: unknown }, cacheKey: string): UrlReputationResult | null {
    const validated = validate(VirusTotalUrlResponseSchema, response.data);
    if (!validated.success) {
      securityLogger.warn('Invalid VT response', { error: validated.error.message, url });
      return null;
    }
    const stats = validated.data.data.attributes.last_analysis_stats;
    const total = stats.malicious + stats.harmless + stats.undetected;
    const result: UrlReputationResult = {
      url,
      malicious: stats.malicious > 0,
      maliciousCount: stats.malicious,
      totalScans: total,
      detectedBy: Object.keys(validated.data.data.attributes.last_analysis_results || {}),
      confidenceScore: total > 0 ? stats.malicious / total : 0,
    };
    this.cache.set(cacheKey, result);
    return result;
  }
}

/** AbuseIPDB API client with retry and circuit breaker */
export class AbuseIPDBClient {
  private client: AxiosInstance;
  private breaker: CircuitBreaker;
  private cache: NodeCache;

  constructor(apiKey: string, cache: NodeCache) {
    this.cache = cache;
    this.client = axios.create({
      baseURL: 'https://api.abuseipdb.com/api/v2',
      headers: { Key: apiKey },
      timeout: config.threatIntel.timeoutMs,
    });
    this.breaker = new CircuitBreaker(
      (ip: string) => this.client.get('/check', { params: { ipAddress: ip } }),
      CIRCUIT_BREAKER_OPTIONS
    );
    this.setupBreakerEvents('AbuseIPDB');
  }

  private setupBreakerEvents(apiName: string): void {
    this.breaker.on('open', () => securityLogger.warn(`${apiName} circuit OPEN`));
    this.breaker.on('halfOpen', () => securityLogger.info(`${apiName} circuit HALF-OPEN`));
    this.breaker.on('close', () => securityLogger.info(`${apiName} circuit CLOSED`));
  }

  async checkIp(ip: string): Promise<IpReputationResult | null> {
    const cacheKey = `abuseipdb-${ip}`;
    const cached = this.cache.get<IpReputationResult>(cacheKey);
    if (cached) return cached;

    try {
      const response = await pRetry(() => this.breaker.fire(ip) as Promise<{ data: unknown }>, {
        ...RETRY_OPTIONS,
        onFailedAttempt: (e) => securityLogger.warn('AbuseIPDB retry', { attempt: e.attemptNumber, ip }),
      });
      return this.parseResponse(ip, response, cacheKey);
    } catch (error: unknown) {
      securityLogger.warn('AbuseIPDB failed', {
        error: getErrorMessage(error),
        ip,
      });
      return null;
    }
  }

  private parseResponse(ip: string, response: { data: unknown }, cacheKey: string): IpReputationResult | null {
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
}
