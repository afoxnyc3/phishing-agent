# RFC-0003: Webhook Migration from Polling

## Status

Proposed

## Context

The agent currently polls the mailbox every 60 seconds via Microsoft Graph API (`src/services/mailbox-monitor.ts`). This results in:

- **1,440+ API calls/day** even with zero emails to process
- **Up to 60-second delay** between email arrival and analysis
- **Wasted resources** — 87% of polling calls return no new emails

Microsoft Graph supports webhook subscriptions that push notifications when new emails arrive, enabling real-time processing.

## Decision

Migrate from polling to **Graph API webhook subscriptions** using a phased approach:

**Phase 1 — Hybrid mode (2-3 weeks):**

- Add webhook endpoint (`POST /webhook/email`) for Graph notifications
- Create Graph subscription on startup, auto-renew every 2 days (3-day TTL)
- Keep polling as fallback at 5-minute intervals (reduced from 60 seconds)
- Validate webhook delivery reliability

**Phase 2 — Webhook-only:**

- Disable polling after 2+ weeks of validated webhook reliability
- Keep fallback route available for manual reactivation

**Webhook flow:**

```
Email arrives → Graph detects new message → POST to /webhook/email
→ Validate notification → Fetch full email via Graph API → Process email
```

**Required new components:**

- `src/services/webhook-handler.ts` — notification endpoint with validation
- `src/services/graph-subscription-manager.ts` — subscription lifecycle management

**Success criteria:**

- Webhook delivery latency <5 seconds
- 99%+ delivery success rate
- Zero missed emails (deduplication layer covers edge cases)

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
- GitHub issues: #38 (webhook endpoint), #39 (subscription management), #40 (async decoupling)
