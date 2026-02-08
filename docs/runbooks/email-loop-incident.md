# Runbook: Email Loop Incident Response

## Symptoms

- Rapid reply generation (multiple replies per minute)
- Rate limiter "exceeded" warnings in logs
- Circuit breaker opens (state: `OPEN` in `/health/deep`)
- Multiple replies sent to the same sender in a short window
- Sudden spike in Graph API send-mail calls

## Detection

```bash
# Check circuit breaker and rate limiter state
curl -s -H "Authorization: Bearer $API_KEY" https://<app>/health/deep | jq '.circuitBreaker, .rateLimiter'

# Search logs for loop indicators
# Look for: "Rate limit exceeded", "Circuit breaker opened", "Duplicate email"
```

## Immediate Actions

### 1. Assess circuit breaker state

```bash
curl -s -H "Authorization: Bearer $API_KEY" https://<app>/health/deep
```

If circuit breaker is already `OPEN`, it has self-protected. If still `CLOSED`, proceed to step 2.

### 2. Stop reply generation

Set environment variable to disable outbound replies:

```bash
# Azure Container Apps
az containerapp update --name phishing-agent --resource-group <rg> \
  --set-env-vars REPLY_ENABLED=false
```

This stops reply sending while analysis continues.

### 3. Check rate limiter logs

Search for rate limiter hits in the last hour:

```
"Rate limit exceeded" OR "sender in cooldown" OR "Duplicate email already processed"
```

### 4. Count recent replies

Check how many replies were sent in the incident window to gauge blast radius.

## Root Cause Checklist

| Guard Layer      | Failure Mode                               | Check                                                 |
| ---------------- | ------------------------------------------ | ----------------------------------------------------- |
| Reply-to-self    | Agent replying to its own analysis replies | Check if sender matches `PHISHING_MAILBOX_ADDRESS`    |
| Recipient filter | External system forwarding replies back    | Check if replies are going to internal-only addresses |
| Dedup hash       | Same email processed multiple times        | Check Redis connectivity, verify dedup hash TTL       |
| Rate limiter     | Limits too high for the traffic pattern    | Review `RATE_LIMIT_*` env vars                        |
| Circuit breaker  | Threshold too high before tripping         | Review `CIRCUIT_BREAKER_*` env vars                   |

## Recovery

1. Identify and fix the root cause from the checklist above
2. Re-enable replies: set `REPLY_ENABLED=true`
3. Monitor for 30 minutes — verify single-reply-per-email behavior
4. Check `/health/deep` to confirm all guards are healthy

## Prevention

- Set up alerting on rate limiter hit count (threshold: >5 hits/hour)
- Set up alerting on circuit breaker state changes
- Review guard layer configuration quarterly
- Test loop scenarios in staging before production changes
