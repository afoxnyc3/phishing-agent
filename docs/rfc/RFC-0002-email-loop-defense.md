# RFC-0002: Email Loop Defense Layers

## Status

Accepted

## Context

On October 20, 2025, the agent entered an email loop and sent 10,000 emails in 24 hours by replying to its own analysis reports. The root cause was the agent processing emails from its own mailbox address without a self-reply guard.

A single guard is insufficient — defense-in-depth is required to prevent loops even if one layer fails.

## Decision

Implement a **5-layer defense-in-depth** architecture in `src/services/email-guards.ts`:

| Layer | Guard                 | Severity | Mechanism                                  |
| ----- | --------------------- | -------- | ------------------------------------------ |
| 1     | Self-reply detection  | Critical | Compare sender to agent mailbox address    |
| 2     | Rate limiter          | Critical | Sliding window: 100/hour, 1000/day         |
| 3     | Circuit breaker       | High     | 50 emails in 10 minutes → block for 1 hour |
| 4     | Content deduplication | Medium   | SHA-256 hash of subject + body, 24h TTL    |
| 5     | Sender cooldown       | Medium   | Max 1 reply per sender per 24 hours        |

All guards execute in `evaluateEmailGuards()` before any email processing begins. Each guard is independent — failure in one layer does not affect others.

**Configuration** (environment variables):

- `MAX_EMAILS_PER_HOUR=100` / `MAX_EMAILS_PER_DAY=1000` (production)
- `CIRCUIT_BREAKER_THRESHOLD=50` / `CIRCUIT_BREAKER_WINDOW_MS=600000`
- Development uses stricter limits (10/hour, 50/day)

## Consequences

**Positive:**

- Maximum damage reduced from 10,000 to ~100 emails per incident
- Each layer is independently testable (106 unit tests)
- Guard checks add <1ms latency per email
- Comprehensive metrics for monitoring (selfRepliesDetected, rateLimitHits, circuitBreakerTrips)

**Negative:**

- Conservative rate limits may throttle legitimate high-volume periods (tunable via env vars)
- In-memory state is lost on restart (Redis-backed versions exist but are optional)
- Sender cooldown means at most 1 reply per sender per day

## References

- [EMAIL_LOOP_PREVENTION.md](../../EMAIL_LOOP_PREVENTION.md) — incident report and full guard documentation
- [AZURE_EMAIL_LOOP_INCIDENT.md](../../AZURE_EMAIL_LOOP_INCIDENT.md) — incident post-mortem
- `src/services/email-guards.ts` — implementation
- `src/services/email-guards.test.ts` — test suite
