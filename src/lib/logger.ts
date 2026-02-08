/**
 * Security-focused logging with Winston
 */

import winston from 'winston';
import { PerformanceMetrics } from './types.js';

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

/**
 * Security logger with specialized methods
 */
export class SecurityLogger {
  private performanceMetrics: PerformanceMetrics[] = [];
  private maxMetrics = 1000;

  info(message: string, meta?: Record<string, unknown>): void {
    logger.info(message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    logger.warn(message, meta);
  }

  error(message: string, error?: unknown): void {
    const err = error as { message?: string; stack?: string } | undefined;
    logger.error(message, { error: err?.message || error, stack: err?.stack });
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    logger.debug(message, meta);
  }

  security(message: string, meta?: Record<string, unknown>): void {
    logger.info(`[SECURITY] ${message}`, meta);
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
