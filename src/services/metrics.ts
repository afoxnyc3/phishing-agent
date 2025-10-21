/**
 * Metrics Service
 * Tracks business and operational metrics for observability
 * Production-ready with Prometheus-compatible format
 */

export interface BusinessMetrics {
  emailsProcessed: number;
  phishingDetected: number;
  legitimateEmails: number;
  analysisErrors: number;
  rateLimitHits: number;
  deduplicationHits: number;
  repliesSent: number;
  repliesFailed: number;
}

export interface LatencyMetrics {
  analysisLatencyMs: number[];
  replyLatencyMs: number[];
}

export class MetricsService {
  private startTime: Date;
  private business: BusinessMetrics;
  private latency: LatencyMetrics;

  constructor() {
    this.startTime = new Date();
    this.business = {
      emailsProcessed: 0,
      phishingDetected: 0,
      legitimateEmails: 0,
      analysisErrors: 0,
      rateLimitHits: 0,
      deduplicationHits: 0,
      repliesSent: 0,
      repliesFailed: 0,
    };
    this.latency = {
      analysisLatencyMs: [],
      replyLatencyMs: [],
    };
  }

  /**
   * Record email processed
   */
  recordEmailProcessed(isPhishing: boolean): void {
    this.business.emailsProcessed++;
    if (isPhishing) {
      this.business.phishingDetected++;
    } else {
      this.business.legitimateEmails++;
    }
  }

  /**
   * Record analysis error
   */
  recordAnalysisError(): void {
    this.business.analysisErrors++;
  }

  /**
   * Record rate limit hit
   */
  recordRateLimitHit(): void {
    this.business.rateLimitHits++;
  }

  /**
   * Record deduplication hit
   */
  recordDeduplicationHit(): void {
    this.business.deduplicationHits++;
  }

  /**
   * Record reply sent
   */
  recordReplySent(): void {
    this.business.repliesSent++;
  }

  /**
   * Record reply failed
   */
  recordReplyFailed(): void {
    this.business.repliesFailed++;
  }

  /**
   * Record analysis latency
   */
  recordAnalysisLatency(durationMs: number): void {
    this.latency.analysisLatencyMs.push(durationMs);
    // Keep only last 1000 measurements
    if (this.latency.analysisLatencyMs.length > 1000) {
      this.latency.analysisLatencyMs.shift();
    }
  }

  /**
   * Record reply latency
   */
  recordReplyLatency(durationMs: number): void {
    this.latency.replyLatencyMs.push(durationMs);
    // Keep only last 1000 measurements
    if (this.latency.replyLatencyMs.length > 1000) {
      this.latency.replyLatencyMs.shift();
    }
  }

  /**
   * Get all metrics
   */
  getMetrics(): {
    uptime: number;
    business: BusinessMetrics;
    latency: {
      analysisP50: number;
      analysisP95: number;
      analysisP99: number;
      replyP50: number;
      replyP95: number;
      replyP99: number;
    };
  } {
    return {
      uptime: Date.now() - this.startTime.getTime(),
      business: { ...this.business },
      latency: {
        analysisP50: this.calculatePercentile(this.latency.analysisLatencyMs, 50),
        analysisP95: this.calculatePercentile(this.latency.analysisLatencyMs, 95),
        analysisP99: this.calculatePercentile(this.latency.analysisLatencyMs, 99),
        replyP50: this.calculatePercentile(this.latency.replyLatencyMs, 50),
        replyP95: this.calculatePercentile(this.latency.replyLatencyMs, 95),
        replyP99: this.calculatePercentile(this.latency.replyLatencyMs, 99),
      },
    };
  }

  /**
   * Get Prometheus-formatted metrics
   */
  getPrometheusMetrics(): string {
    const metrics = this.getMetrics();
    return `
# HELP phishing_agent_uptime_ms Service uptime in milliseconds
# TYPE phishing_agent_uptime_ms gauge
phishing_agent_uptime_ms ${metrics.uptime}

# HELP phishing_agent_emails_processed_total Total emails processed
# TYPE phishing_agent_emails_processed_total counter
phishing_agent_emails_processed_total ${metrics.business.emailsProcessed}

# HELP phishing_agent_phishing_detected_total Total phishing emails detected
# TYPE phishing_agent_phishing_detected_total counter
phishing_agent_phishing_detected_total ${metrics.business.phishingDetected}

# HELP phishing_agent_legitimate_emails_total Total legitimate emails
# TYPE phishing_agent_legitimate_emails_total counter
phishing_agent_legitimate_emails_total ${metrics.business.legitimateEmails}

# HELP phishing_agent_analysis_errors_total Total analysis errors
# TYPE phishing_agent_analysis_errors_total counter
phishing_agent_analysis_errors_total ${metrics.business.analysisErrors}

# HELP phishing_agent_rate_limit_hits_total Total rate limit hits
# TYPE phishing_agent_rate_limit_hits_total counter
phishing_agent_rate_limit_hits_total ${metrics.business.rateLimitHits}

# HELP phishing_agent_deduplication_hits_total Total deduplication hits
# TYPE phishing_agent_deduplication_hits_total counter
phishing_agent_deduplication_hits_total ${metrics.business.deduplicationHits}

# HELP phishing_agent_replies_sent_total Total replies sent
# TYPE phishing_agent_replies_sent_total counter
phishing_agent_replies_sent_total ${metrics.business.repliesSent}

# HELP phishing_agent_replies_failed_total Total replies failed
# TYPE phishing_agent_replies_failed_total counter
phishing_agent_replies_failed_total ${metrics.business.repliesFailed}

# HELP phishing_agent_analysis_latency_ms Analysis latency percentiles
# TYPE phishing_agent_analysis_latency_ms gauge
phishing_agent_analysis_latency_ms{quantile="0.5"} ${metrics.latency.analysisP50}
phishing_agent_analysis_latency_ms{quantile="0.95"} ${metrics.latency.analysisP95}
phishing_agent_analysis_latency_ms{quantile="0.99"} ${metrics.latency.analysisP99}

# HELP phishing_agent_reply_latency_ms Reply latency percentiles
# TYPE phishing_agent_reply_latency_ms gauge
phishing_agent_reply_latency_ms{quantile="0.5"} ${metrics.latency.replyP50}
phishing_agent_reply_latency_ms{quantile="0.95"} ${metrics.latency.replyP95}
phishing_agent_reply_latency_ms{quantile="0.99"} ${metrics.latency.replyP99}
`.trim();
  }

  /**
   * Calculate percentile from array
   */
  private calculatePercentile(values: number[], percentile: number): number {
    if (values.length === 0) return 0;

    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  /**
   * Reset all metrics (for testing)
   */
  reset(): void {
    this.startTime = new Date();
    this.business = {
      emailsProcessed: 0,
      phishingDetected: 0,
      legitimateEmails: 0,
      analysisErrors: 0,
      rateLimitHits: 0,
      deduplicationHits: 0,
      repliesSent: 0,
      repliesFailed: 0,
    };
    this.latency = {
      analysisLatencyMs: [],
      replyLatencyMs: [],
    };
  }
}

// Global metrics instance
export const metrics = new MetricsService();
