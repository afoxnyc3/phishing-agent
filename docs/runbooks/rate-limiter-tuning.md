# Runbook: Rate Limiter Tuning

## When to Adjust

**Too restrictive** (false positives):

- Legitimate forwarded emails are being blocked
- Users report "no reply received" for emails they forwarded
- Rate limiter "exceeded" messages for distinct senders

**Too permissive** (loops not caught):

- Multiple replies sent before circuit breaker trips
- Reply volume exceeds expected throughput

## Current Defaults

| Setting            | Default  | Description                                    |
| ------------------ | -------- | ---------------------------------------------- |
| Max replies/sender | 3/hour   | Per-sender sliding window                      |
| Global max replies | 50/hour  | System-wide circuit breaker input              |
| Sender cooldown    | 1 hour   | Minimum gap between replies to same sender     |
| Dedup hash TTL     | 24 hours | How long processed email hashes are remembered |

## How to Change

### Environment variables

```bash
# Per-sender rate limit
RATE_LIMIT_MAX_PER_SENDER=5        # Increase for high-volume forwarders
RATE_LIMIT_WINDOW_MS=3600000       # Window size (default: 1 hour)

# Deduplication
DEDUP_CONTENT_HASH_TTL_MS=86400000 # 24 hours (how long to remember emails)
DEDUP_SENDER_COOLDOWN_MS=3600000   # 1 hour (min gap between replies)
```

Apply via Azure Container Apps:

```bash
az containerapp update --name phishing-agent --resource-group <rg> \
  --set-env-vars RATE_LIMIT_MAX_PER_SENDER=5
```

### Redis keys (live adjustment)

If using Redis-backed rate limiting, keys can be inspected and cleared without restart:

```bash
# View current rate limit state for a sender
redis-cli ZRANGE "v1:rate:window:sender@example.com" 0 -1 WITHSCORES

# Clear rate limit for a specific sender (allows immediate reply)
redis-cli DEL "v1:rate:window:sender@example.com"

# Clear all rate limit state (use with caution)
redis-cli KEYS "v1:rate:*" | xargs redis-cli DEL
```

### In-memory mode

If not using Redis, rate limit state is per-process and resets on restart:

```bash
# Restart clears all in-memory rate limit state
az containerapp revision restart --name phishing-agent --resource-group <rg>
```

## Monitoring After Changes

Watch these metrics for 24 hours after any rate limit adjustment:

1. **Reply count per hour** — should stay within new limits
2. **Rate limiter hit rate** — should decrease if limits were raised
3. **Unique senders processed** — baseline for normal volume
4. **Circuit breaker state** — should remain `CLOSED`

## Escalation

If rate limiter tuning alone doesn't solve the issue:

1. Check if the circuit breaker needs adjustment (`CIRCUIT_BREAKER_THRESHOLD`)
2. Review the dedup hash to ensure it's working (not generating different hashes for same email)
3. Check if a mail rule or auto-forward is creating a feedback loop
4. Consider temporarily disabling replies (`REPLY_ENABLED=false`) while investigating
