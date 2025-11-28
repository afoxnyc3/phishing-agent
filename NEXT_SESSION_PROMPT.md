# Next Session Prompt

You are Codex, a senior Azure/Node.js engineer. Continue from the previous audit and implement the highest-impact improvements. Follow the instructions below exactly.

## Objectives
- Implement top-priority security and reliability fixes for the phishing-agent service.
- Keep outputs deterministic and enterprise-safe for production on Azure.

## Prioritized Work Items
1) **Outbound safety**: Enforce explicit sender allowlists (emails/domains) in `email-processor.ts` guardrails. In production, fail-closed when allowlists are empty. Avoid backscatter/auto-replies to untrusted senders.
2) **Identity & secrets**: Move Graph auth to Managed Identity where supported; otherwise require `AZURE_CLIENT_SECRET` in prod. Enforce Key Vault usage (`AZURE_KEY_VAULT_NAME`) in prod startup.
3) **Ops endpoints protection**: Require auth for `/health`, `/health/deep`, `/ready`, `/metrics`; prefer AAD/JWT validation. Add body size limits, `helmet`, and cached deep health (30–60s). Avoid live Graph calls per request.
4) **Distributed rate limit & dedup**: Move rate limiting, dedup, and message-id cache to Redis (Azure Cache). Use TTL keys for messageId/content hash/sender cooldown; ensure multi-replica consistency.
5) **Mailbox ingestion reliability**: Add Graph delta/nextLink or move to change notifications + queue. Process in parallel with bounded concurrency (`p-limit`) and checkpoint last sync.

## Constraints & Quality Bar
- Node 18+; prefer Node 22-alpine for containers. No secrets in code. Keep ASCII.
- Add/adjust tests for new logic. Update configs/schemas so prod fails fast if required env is missing.
- Maintain existing logging style but add correlation IDs when feasible. Avoid PII in logs.

## Deliverables
- Code changes implementing items above with clear in-code comments only where non-obvious.
- Updated docs/config samples if env vars change.
- Brief summary of changes and tests run.

## Execution Order
1) Outbound safety guardrails (allowlist fail-closed).
2) Identity/Key Vault enforcement.
3) Ops endpoint hardening (auth, limits, caching).
4) Redis-backed rate limit & dedup.
5) Mailbox ingestion robustness (delta/queue + concurrency).

## Definition of Done
- All new checks gated for production; tests updated/passing.
- No unauthenticated operational endpoints in prod.
- Rate limiting/deduplication resilient across replicas.
- Mailbox ingestion will not drop messages under pagination/bursts.
