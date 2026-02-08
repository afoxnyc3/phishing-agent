/**
 * Correlation Metrics
 * Tracks custom metrics for operational visibility across the email processing lifecycle.
 * Designed for future Application Insights integration.
 */

const MAX_SAMPLES = 1000;

/** Guard types that can block email processing */
export type GuardType =
  | 'duplicate-message-id'
  | 'self-sender-detected'
  | 'sender-not-allowlisted'
  | 'auto-responder-detected'
  | 'missing-sender'
  | 'missing-message-id'
  | 'rate-limit'
  | 'deduplication'
  | 'circuit-breaker'
  | 'recipient-filter';

export interface CorrelationMetricsSnapshot {
  analysisDurations: { p50: number; p95: number; p99: number; count: number };
  riskScoreDistribution: { p50: number; p95: number; mean: number; count: number };
  loopPreventionHits: Record<string, number>;
  webhookToProcessLatency: { p50: number; p95: number; count: number };
  guardPassRate: { passed: number; blocked: number; rate: number };
}

export class CorrelationMetrics {
  private analysisDurationsMs: number[] = [];
  private riskScores: number[] = [];
  private guardHits: Map<string, number> = new Map();
  private guardPassed = 0;
  private guardBlocked = 0;
  private webhookLatencies: number[] = [];

  /** Record total analysis duration (arrival to analysis complete) */
  recordAnalysisDuration(durationMs: number): void {
    this.analysisDurationsMs.push(durationMs);
    this.trimArray(this.analysisDurationsMs);
  }

  /** Record a risk score from a completed analysis */
  recordRiskScore(score: number): void {
    this.riskScores.push(score);
    this.trimArray(this.riskScores);
  }

  /** Record a loop prevention / guard hit by type */
  recordGuardHit(guardType: GuardType): void {
    const current = this.guardHits.get(guardType) ?? 0;
    this.guardHits.set(guardType, current + 1);
    this.guardBlocked++;
  }

  /** Record that an email passed all guards */
  recordGuardPass(): void {
    this.guardPassed++;
  }

  /** Record webhook-to-process latency */
  recordWebhookLatency(latencyMs: number): void {
    this.webhookLatencies.push(latencyMs);
    this.trimArray(this.webhookLatencies);
  }

  /** Get a snapshot of all correlation metrics */
  getSnapshot(): CorrelationMetricsSnapshot {
    const total = this.guardPassed + this.guardBlocked;
    return {
      analysisDurations: {
        p50: this.percentile(this.analysisDurationsMs, 50),
        p95: this.percentile(this.analysisDurationsMs, 95),
        p99: this.percentile(this.analysisDurationsMs, 99),
        count: this.analysisDurationsMs.length,
      },
      riskScoreDistribution: {
        p50: this.percentile(this.riskScores, 50),
        p95: this.percentile(this.riskScores, 95),
        mean: this.mean(this.riskScores),
        count: this.riskScores.length,
      },
      loopPreventionHits: Object.fromEntries(this.guardHits),
      webhookToProcessLatency: {
        p50: this.percentile(this.webhookLatencies, 50),
        p95: this.percentile(this.webhookLatencies, 95),
        count: this.webhookLatencies.length,
      },
      guardPassRate: {
        passed: this.guardPassed,
        blocked: this.guardBlocked,
        rate: total > 0 ? this.guardPassed / total : 0,
      },
    };
  }

  /** Get Prometheus-formatted correlation metrics */
  getPrometheusMetrics(): string {
    const snap = this.getSnapshot();
    return [
      '# HELP phishing_agent_analysis_duration_ms End-to-end analysis duration',
      '# TYPE phishing_agent_analysis_duration_ms summary',
      `phishing_agent_analysis_duration_ms{quantile="0.5"} ${snap.analysisDurations.p50}`,
      `phishing_agent_analysis_duration_ms{quantile="0.95"} ${snap.analysisDurations.p95}`,
      `phishing_agent_analysis_duration_ms{quantile="0.99"} ${snap.analysisDurations.p99}`,
      `phishing_agent_analysis_duration_ms_count ${snap.analysisDurations.count}`,
      '',
      '# HELP phishing_agent_risk_score Risk score distribution',
      '# TYPE phishing_agent_risk_score summary',
      `phishing_agent_risk_score{quantile="0.5"} ${snap.riskScoreDistribution.p50}`,
      `phishing_agent_risk_score{quantile="0.95"} ${snap.riskScoreDistribution.p95}`,
      `phishing_agent_risk_score_mean ${snap.riskScoreDistribution.mean}`,
      `phishing_agent_risk_score_count ${snap.riskScoreDistribution.count}`,
      '',
      '# HELP phishing_agent_guard_hits Loop prevention hits by guard type',
      '# TYPE phishing_agent_guard_hits counter',
      ...Object.entries(snap.loopPreventionHits).map(
        ([type, count]) => `phishing_agent_guard_hits{guard="${type}"} ${count}`
      ),
      '',
      '# HELP phishing_agent_webhook_latency_ms Webhook to processing start latency',
      '# TYPE phishing_agent_webhook_latency_ms summary',
      `phishing_agent_webhook_latency_ms{quantile="0.5"} ${snap.webhookToProcessLatency.p50}`,
      `phishing_agent_webhook_latency_ms{quantile="0.95"} ${snap.webhookToProcessLatency.p95}`,
      `phishing_agent_webhook_latency_ms_count ${snap.webhookToProcessLatency.count}`,
      '',
      '# HELP phishing_agent_guard_pass_rate Guard pass rate',
      '# TYPE phishing_agent_guard_pass_rate gauge',
      `phishing_agent_guard_pass_rate ${snap.guardPassRate.rate}`,
      `phishing_agent_guard_passed_total ${snap.guardPassRate.passed}`,
      `phishing_agent_guard_blocked_total ${snap.guardPassRate.blocked}`,
    ].join('\n');
  }

  /** Reset all metrics (for testing) */
  reset(): void {
    this.analysisDurationsMs = [];
    this.riskScores = [];
    this.guardHits.clear();
    this.guardPassed = 0;
    this.guardBlocked = 0;
    this.webhookLatencies = [];
  }

  private trimArray(arr: number[]): void {
    while (arr.length > MAX_SAMPLES) {
      arr.shift();
    }
  }

  private percentile(values: number[], pct: number): number {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const idx = Math.ceil((pct / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
  }

  private mean(values: number[]): number {
    if (values.length === 0) return 0;
    const sum = values.reduce((a, b) => a + b, 0);
    return Math.round((sum / values.length) * 100) / 100;
  }
}

/** Global correlation metrics instance */
export const correlationMetrics = new CorrelationMetrics();
