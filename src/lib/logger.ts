/**
 * Security-focused logging with Winston
 */

import winston from 'winston';
import { PerformanceMetrics } from './types.js';
import { getErrorMessage } from './errors.js';
import { piiRedactor } from './pii-redactor.js';
import { getCorrelationId } from './correlation.js';

// Winston logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
  ],
});

/** Enrich metadata with correlation ID from async context */
function enrichWithCorrelation(meta?: Record<string, unknown>): Record<string, unknown> {
  const correlationId = getCorrelationId();
  const base = meta ? piiRedactor.redactObject(meta) : {};
  if (correlationId === 'none') return meta ? base : {};
  return { correlationId, ...base };
}

/** Check if enriched metadata has any keys beyond correlationId */
function hasContent(enriched: Record<string, unknown>): boolean {
  return Object.keys(enriched).length > 0;
}

/**
 * Security logger with specialized methods
 */
export class SecurityLogger {
  private performanceMetrics: PerformanceMetrics[] = [];
  private maxMetrics = 1000;

  info(message: string, meta?: Record<string, unknown>): void {
    const enriched = enrichWithCorrelation(meta);
    logger.info(message, hasContent(enriched) ? enriched : undefined);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    const enriched = enrichWithCorrelation(meta);
    logger.warn(message, hasContent(enriched) ? enriched : undefined);
  }

  error(message: string, error?: unknown): void {
    const correlationId = getCorrelationId();
    const corrMeta = correlationId !== 'none' ? { correlationId } : {};

    if (error instanceof Error) {
      const base = piiRedactor.redactObject({ error: error.message, stack: error.stack });
      logger.error(message, { ...corrMeta, ...base });
    } else if (error != null && typeof error === 'object') {
      const base = piiRedactor.redactObject(error as Record<string, unknown>);
      logger.error(message, { ...corrMeta, ...base });
    } else {
      const base = error !== undefined ? { error: getErrorMessage(error) } : {};
      const merged = { ...corrMeta, ...base };
      logger.error(message, Object.keys(merged).length > 0 ? merged : undefined);
    }
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    const enriched = enrichWithCorrelation(meta);
    logger.debug(message, hasContent(enriched) ? enriched : undefined);
  }

  security(message: string, meta?: Record<string, unknown>): void {
    const enriched = enrichWithCorrelation(meta);
    logger.info(`[SECURITY] ${message}`, hasContent(enriched) ? enriched : undefined);
  }

  addPerformanceMetric(metric: PerformanceMetrics): void {
    this.performanceMetrics.push(metric);
    if (this.performanceMetrics.length > this.maxMetrics) {
      this.performanceMetrics.shift();
    }
  }

  getPerformanceMetrics(hours: number = 1): PerformanceMetrics[] {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    return this.performanceMetrics.filter((m) => m.timestamp >= since);
  }

  cleanup(): void {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    this.performanceMetrics = this.performanceMetrics.filter((m) => m.timestamp >= oneHourAgo);
  }
}

/**
 * Performance timer utility
 */
export class PerformanceTimer {
  private startTime: number;

  constructor(private operation: string) {
    this.startTime = Date.now();
    securityLogger.debug(`Starting: ${operation}`);
  }

  end(success: boolean, errorMessage?: string): void {
    const duration = Date.now() - this.startTime;

    const metric: PerformanceMetrics = {
      timestamp: new Date(),
      operation: this.operation,
      duration,
      success,
      ...(errorMessage && { errorMessage }),
    };

    securityLogger.addPerformanceMetric(metric);

    if (success) {
      securityLogger.debug(`Completed: ${this.operation} (${duration}ms)`);
    } else {
      securityLogger.warn(`Failed: ${this.operation} (${duration}ms)`, { errorMessage });
    }
  }
}

// Export singleton instance
export const securityLogger = new SecurityLogger();
