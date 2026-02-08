/**
 * Webhook Arrival Times
 * Stores timestamps of webhook notifications for latency tracking.
 * Entries expire after TTL to prevent unbounded memory growth.
 */

const TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_ENTRIES = 5000;

export class WebhookArrivalTimes {
  private times: Map<string, number> = new Map();

  /** Record a webhook arrival timestamp for a message ID */
  record(messageId: string, timestamp: number): void {
    if (this.times.size >= MAX_ENTRIES) {
      this.cleanup();
    }
    this.times.set(messageId, timestamp);
  }

  /** Get and remove the arrival time for a message ID */
  consume(messageId: string): number | undefined {
    const timestamp = this.times.get(messageId);
    if (timestamp !== undefined) {
      this.times.delete(messageId);
    }
    return timestamp;
  }

  /** Remove expired entries */
  private cleanup(): void {
    const cutoff = Date.now() - TTL_MS;
    for (const [id, ts] of this.times.entries()) {
      if (ts < cutoff) this.times.delete(id);
    }
  }

  /** Get current entry count (for testing) */
  get size(): number {
    return this.times.size;
  }

  /** Clear all entries (for testing) */
  clear(): void {
    this.times.clear();
  }
}

/** Global instance */
export const webhookArrivalTimes = new WebhookArrivalTimes();
