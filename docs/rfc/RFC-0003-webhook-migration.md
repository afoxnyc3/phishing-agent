# RFC-0003: Webhook Migration from Polling

## Status

Accepted

## Context

The agent currently polls the mailbox every 60 seconds via Microsoft Graph API (`src/services/mailbox-monitor.ts`). This results in:

- **1,440+ API calls/day** even with zero emails to process
- **Up to 60-second delay** between email arrival and analysis
- **Wasted resources** — 87% of polling calls return no new emails

Microsoft Graph supports webhook subscriptions that push notifications when new emails arrive, enabling real-time processing.

## Decision

Migrate from polling to **Graph API webhook subscriptions** using a phased approach:

**Phase 1 — Hybrid mode (2-3 weeks):**

- Add webhook endpoint (`POST /webhooks/mail`) for Graph notifications
- Create Graph subscription on startup, auto-renew every 2 days (3-day TTL)
- Keep polling as fallback at 5-minute intervals (reduced from 60 seconds)
- Validate webhook delivery reliability

**Phase 2 — Webhook-only:**

- Disable polling after 2+ weeks of validated webhook reliability
- Keep fallback route available for manual reactivation

**Webhook flow:**

```
Email arrives → Graph detects new message → POST to /webhooks/mail
→ Validate clientState → Return 202 → Queue for processing
→ Fetch full email via Graph API → Run analysis pipeline → Send reply
```

**Required new components:**

- `src/services/webhook-handler.ts` — notification validation and payload parsing
- `src/services/webhook-route.ts` — Express route for POST /webhooks/mail
- `src/services/graph-subscription-manager.ts` — subscription lifecycle management

**Success criteria:**

- Webhook delivery latency <5 seconds
- 99%+ delivery success rate
- Zero missed emails (deduplication layer covers edge cases)

### Three-Layer Notification Strategy

1. **Primary: Graph API Webhooks** (real-time, <10s latency)
   - POST /webhooks/mail receives change notifications
   - `clientState` verification prevents spoofing
   - Returns 202 before processing (non-blocking)

2. **Secondary: Hourly Timer Fallback** (safety net)
   - Polls every hour with 2-hour lookback window
   - Catches any emails missed by webhooks
   - Dedup prevents double-processing
   - Configurable via `MAIL_MONITOR_ENABLED` and `MAIL_MONITOR_INTERVAL_MS`

3. **Legacy: 60s Polling** (disableable)
   - Original polling mechanism
   - Can be disabled via `POLLING_ENABLED=false` when webhook reliability confirmed
   - Kept available for instant rollback

### Expected Latency Improvement

| Mode              | Average Latency | API Calls/Day |
| ----------------- | --------------- | ------------- |
| Polling (current) | ~65 seconds     | 1,440+        |
| Webhook (target)  | <10 seconds     | ~42           |

Measurement plan: Track `webhook_to_process_latency_ms` metric in Application Insights.

### Rollback Procedure

If webhook delivery becomes unreliable:

1. Set `POLLING_ENABLED=true` (restores 60s polling immediately)
2. Verify emails are being processed via `GET /health/deep`
3. Optionally disable webhook subscription via Graph API
4. Investigate webhook delivery failures in Application Insights
5. Re-enable webhooks after root cause is resolved

No deployment required — all changes are environment variable toggles.

## Consequences

**Positive:**

- Real-time email processing (seconds vs minutes)
- ~97% reduction in API calls (42/day vs 1,560/day)
- Event-driven architecture handles traffic spikes naturally
- Aligns with invoice-agent webhook pattern (ADR-0021)

**Negative:**

- Requires HTTPS endpoint (already provided by Container Apps)
- Subscription renewal adds operational complexity
- Webhook delivery failures require fallback strategy
- Async notification may arrive before email is fully indexed (needs brief delay)

## References

- [Microsoft Graph webhooks documentation](https://learn.microsoft.com/en-us/graph/webhooks)
- invoice-agent ADR-0021 — webhook migration decision (prior art)
- `src/services/mailbox-monitor.ts` — current polling implementation
- GitHub issues: #38 (webhook endpoint), #39 (subscription management), #40 (async decoupling), #41 (timer fallback), #42 (polling disable)
