# Decision Log

This document tracks significant technical and architectural decisions made during the development of phishing-agent.

---

## Decision: Split Content Analyzer into Focused Modules

**Date**: 2025-11-29
**Status**: Accepted
**Context**: `content-analyzer.ts` exceeded 200-line ESLint limit (400 lines), requiring an `eslint-disable` workaround.

**Decision**: Split into 4 focused modules following single-responsibility principle:

- `content-analyzer.ts` (164 lines) - Orchestration layer
- `url-analyzer.ts` (147 lines) - URL extraction, validation, link mismatch detection
- `social-engineering-detector.ts` (83 lines) - Urgency, credential, financial lure detection
- `brand-detector.ts` (51 lines) - Brand impersonation and typosquatting

**Rationale**:

- Each module has clear single responsibility
- All files now comply with 200-line limit
- Maintains backward-compatible public API
- Follows existing codebase patterns (e.g., threat-intel service/client split)
- Link mismatch kept with URL analyzer (both analyze links)
- Brand detection uses existing config file

**Consequences**:

- ✅ All 661 tests pass unchanged
- ✅ No API changes for consumers
- ✅ ESLint now passes without disable comments
- ✅ Easier to maintain and test individual concerns
- ⚠️ 3 additional files to maintain

**Alternatives Considered**:

- 4-file split per issue suggestion (rejected: link-mismatch too small for own file)
- 2-file split (rejected: content-analyzer.ts would still be ~180 lines)

---

## Decision: Use Microsoft Graph API for Email Monitoring

**Date**: 2025-10-16
**Status**: Accepted
**Context**: Need reliable email monitoring for phishing@company.com mailbox.

**Decision**: Use Microsoft Graph API with app-only authentication instead of IMAP/SMTP.

**Rationale**:

- Native Azure AD integration (no additional credentials)
- Better security (app-only auth with Managed Identity)
- Rich email metadata (headers, attachments, body)
- Reliable polling with date filtering
- Same API used for sending replies

**Consequences**:

- ✅ More secure than IMAP credentials
- ✅ Easier deployment in Azure
- ✅ Better structured email data
- ⚠️ Requires Azure AD app registration
- ⚠️ Limited to Microsoft 365 mailboxes

**Alternatives Considered**:

- IMAP/SMTP (rejected: less secure, more complex auth)
- POP3 (rejected: no header access, destructive polling)
- SendGrid/Mailgun (rejected: requires external service)

---

## Decision: Simplified Analysis Engine (No AI/LLM)

**Date**: 2025-10-16
**Status**: Accepted
**Context**: Original project used Claude API for enhanced analysis.

**Decision**: Use deterministic rule-based phishing detection without LLM.

**Rationale**:

- Faster analysis (<5s vs 10-30s with LLM)
- Lower operational costs (no API fees)
- More predictable and auditable results
- Sufficient accuracy for common phishing patterns
- Can add LLM enrichment later as optional feature

**Consequences**:

- ✅ Faster response times
- ✅ Lower infrastructure costs
- ✅ Deterministic behavior
- ⚠️ May miss sophisticated phishing attacks
- ⚠️ Requires manual rule updates

**Alternatives Considered**:

- Claude API integration (rejected: slow, expensive for MVP)
- GPT-4 integration (rejected: same issues as Claude)
- Hybrid approach (deferred: add in v2 if needed)

---

## Decision: Atomic Functions (<25 Lines)

**Date**: 2025-10-16
**Status**: Accepted
**Context**: Need maintainable, testable, predictable code.

**Decision**: Enforce max 25 lines per function, max 150 lines per file.

**Rationale**:

- Easier to test (one function = one test)
- Easier to understand (single responsibility)
- Easier to debug (small surface area)
- Prevents feature creep and over-engineering
- Forces thoughtful decomposition

**Consequences**:

- ✅ Highly testable codebase
- ✅ Easy code reviews
- ✅ Low cognitive load
- ⚠️ More files (but better organized)
- ⚠️ Requires discipline to maintain

---

## Decision: Optional Threat Intel Integration

**Date**: 2025-10-16
**Status**: Accepted
**Context**: Need external reputation checks for URLs/IPs/domains.

**Decision**: Make threat intel APIs optional (VirusTotal, AbuseIPDB, URLScan).

**Rationale**:

- Not all users have API keys
- Basic analysis works without external services
- Graceful degradation if APIs unavailable
- Can add more providers easily

**Consequences**:

- ✅ Works without API keys
- ✅ No external dependencies for MVP
- ✅ Easy to add new providers
- ⚠️ Lower detection accuracy without threat intel
- ⚠️ Need caching to avoid rate limits

---

## Decision: HTML Email Replies (Not Adaptive Cards)

**Date**: 2025-10-16
**Status**: Accepted
**Context**: Need user-friendly analysis results delivery.

**Decision**: Send HTML-formatted email replies instead of Teams Adaptive Cards.

**Rationale**:

- Email-triggered workflow (not Teams-based)
- Users expect email replies to email queries
- HTML allows rich formatting (tables, colors, badges)
- Works across all email clients
- No additional infrastructure needed

**Consequences**:

- ✅ Native email experience
- ✅ Works everywhere (desktop, mobile, webmail)
- ✅ No Teams dependency
- ⚠️ Less interactive than Adaptive Cards
- ⚠️ Limited to email client capabilities

---

## Decision: Custom Async Orchestration for Threat Intel

**Date**: 2025-10-16
**Status**: Accepted
**Context**: Need to enrich phishing analysis with external threat intelligence (VirusTotal, AbuseIPDB, URLScan) for emails that bypassed Mimecast.

**Decision**: Use custom async orchestration with `Promise.allSettled()` and timeout wrappers instead of agent orchestration framework.

**Rationale**:

- No LLM needed → No orchestration framework needed
- Parallel API calls handled perfectly by `Promise.allSettled()`
- Timeout protection with `Promise.race()` prevents hanging
- Rate limiting via `p-limit` library (10 req/s)
- Caching via `node-cache` (5-min TTL) reduces duplicate calls
- Graceful degradation (analysis continues even if APIs fail)

**Consequences**:

- ✅ Fast parallel execution (2-3s for 3 APIs)
- ✅ No framework complexity or learning curve
- ✅ Full control over timeouts and retries
- ✅ Easy to test (mock individual API clients)
- ⚠️ Manual timeout/retry logic (but simple with Promise patterns)
- ⚠️ Need to manage caching manually (but `node-cache` is trivial)

**Alternatives Considered**:

- LangChain (rejected: massive overkill, no LLM needed)
- Anthropic/OpenAI SDK (rejected: no LLM needed)
- AI SDK (rejected: UI-focused, not server-side)
- Custom orchestration with RxJS (rejected: simpler with Promises)

---

## Template for New Decisions

```markdown
## Decision: [Title]

**Date**: YYYY-MM-DD
**Status**: [Proposed | Accepted | Deprecated | Superseded]
**Context**: Brief description of the problem.

**Decision**: What was decided.

**Rationale**:

- Reason 1
- Reason 2
- Reason 3

**Consequences**:

- ✅ Positive outcome 1
- ✅ Positive outcome 2
- ⚠️ Trade-off 1
- ❌ Negative consequence (if any)

**Alternatives Considered**:

- Option A (rejected: reason)
- Option B (rejected: reason)
```
