# Agent Design Philosophy

**Purpose**: This document explains the design principles, decision-making framework, and implementation approach for the phishing detection agent.

**Last Updated**: 2025-11-29
**Version**: v0.3.1

---

## Overview

The phishing agent is a rule-based email analysis system designed to detect phishing attempts through systematic evaluation of email headers, content patterns, and threat intelligence. It uses transparent, explainable rules that security teams can audit and tune, with optional LLM-enhanced analysis for borderline cases requiring natural language explanations.

### Design Goals

1. **Fast Analysis**: Complete evaluation in under 5 seconds
2. **Explainable Results**: Every detection backed by specific evidence
3. **Low False Positives**: Conservative scoring to avoid alert fatigue
4. **Graceful Degradation**: Continue operation even when external services fail
5. **User-Friendly Output**: Clear, actionable recommendations for non-technical users

---

## Core Analysis Pipeline

The agent processes each email through a sequential pipeline:

```
Email Input
    ↓
Header Validation (SPF, DKIM, DMARC)
    ↓
Content Analysis (URLs, Keywords, Patterns)
    ↓
Attachment Analysis (Executables, Macros, Archives)
    ↓
Threat Intelligence Enrichment (Optional)
    ↓
Risk Scoring (0-10 scale, weighted aggregation)
    ↓
LLM Explanation (Optional, for borderline cases)
    ↓
Verdict Generation & Email Reply
```

### Pipeline Characteristics

- **Stateless**: Each email analyzed independently
- **Atomic Operations**: Each validation function is < 25 lines
- **Fail-Safe**: Pipeline continues even if individual checks fail
- **Parallel Processing**: Threat intel APIs called concurrently

---

## Risk Scoring Methodology

### Scoring Framework

The agent calculates a risk score (0-10) by aggregating findings from multiple analysis layers:

**Authentication Failures** (+2.0 points each):

- SPF (Sender Policy Framework) failure
- DKIM (DomainKeys Identified Mail) failure
- DMARC (Domain-based Message Authentication) failure

**Suspicious URLs** (+1.5 points each):

- IP addresses in links
- Shortened URLs (bit.ly, tinyurl, etc.)
- Typosquatting domains (paypa1.com)
- Uncommon TLDs (.xyz, .top, .loan)

**Content Patterns** (variable points):

- Brand impersonation (+2.0)
- Urgency keywords (+1.0)
- Credential harvesting language (+1.5)
- Wire transfer requests (+2.0)

**Threat Intelligence** (up to +3.0):

- Known malicious URL/domain (+2.0)
- Suspicious sender IP (+1.5)
- Recent phishing campaign match (+2.5)

**Attachment Risks** (variable points):

- Dangerous executables (.exe, .bat, .vbs, .scr) - CRITICAL (+2.5)
- Macro-enabled documents (.docm, .xlsm) - HIGH (+1.5)
- Double extension tricks (invoice.pdf.exe) - CRITICAL (+2.5)
- Archive files (.zip, .rar, .iso) - MEDIUM (+0.75)
- Suspicious file sizes (too small/large) - MEDIUM (+0.75)

### Score Weighting

When attachments are present, scores are weighted:

- **With attachments**: Header (40%) + Content (30%) + Attachment (30%)
- **Without attachments**: Header (60%) + Content (40%)

### Severity Mapping

Risk scores map to severity levels:

| Score Range | Severity     | User Impact                                         |
| ----------- | ------------ | --------------------------------------------------- |
| 0.0 - 4.9   | **LOW**      | Email likely legitimate                             |
| 5.0 - 6.9   | **MEDIUM**   | Caution advised, user training opportunity          |
| 7.0 - 8.9   | **HIGH**     | Strong phishing indicators, recommend quarantine    |
| 9.0 - 10.0  | **CRITICAL** | High-confidence phishing, immediate action required |

---

## Decision-Making Framework

### HIGH RISK (Score ≥ 7.0)

**Indicators**:

- Multiple authentication failures
- Known malicious URLs or sender IPs
- Credential harvesting patterns
- Brand impersonation with urgency tactics

**Recommended Actions**:

- Quarantine email immediately
- Block sender domain if persistent
- Report to security team
- User training on phishing recognition

### MEDIUM RISK (Score 5.0-6.9)

**Indicators**:

- Some authentication failures
- Suspicious but unconfirmed patterns
- Generic urgency language
- Unusual sender behavior

**Recommended Actions**:

- Flag for user caution
- Provide educational context
- Monitor sender for patterns
- Consider additional verification

### LOW RISK (Score < 5.0)

**Indicators**:

- Passes all authentication checks
- No suspicious content patterns
- Known legitimate sender
- Normal email characteristics

**Recommended Actions**:

- Mark as likely legitimate
- Educate on what makes it safe
- Reinforce security awareness
- Allow normal processing

---

## Email Reply Design

### Template Structure

Each analysis result is delivered via HTML-formatted email reply:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[VERDICT: PHISHING DETECTED / EMAIL APPEARS SAFE]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Assessment:
┌──────────────┬────────────┐
│ Risk Score   │ 8.5/10     │
│ Severity     │ HIGH       │
│ Confidence   │ 95%        │
└──────────────┴────────────┘

Threat Indicators:
• SPF authentication failed (HIGH)
• Suspicious URL with IP address (CRITICAL)
• Brand impersonation detected (HIGH)

Recommended Actions:
✓ Do NOT click any links
✓ Do NOT provide credentials
✓ Report to IT team
```

### Design Principles

1. **Color-Coded Verdicts**: Red for phishing, green for safe
2. **Evidence-Based**: List specific findings, not generic warnings
3. **Actionable**: Clear next steps for the user
4. **Mobile-Responsive**: Readable on all devices
5. **Top 5 Indicators**: Prioritize most important findings

---

## Code Quality Standards

### Atomic Functions

Every function adheres to strict simplicity rules:

**Maximum 25 Lines**:

```typescript
// Good: Single responsibility, clear logic
export function validateSpfRecord(spfHeader: string | undefined): Result<string, Error> {
  if (!spfHeader) {
    return { success: false, error: new Error('No SPF header found') };
  }

  const normalized = spfHeader.toLowerCase();

  if (normalized.includes('fail')) {
    return { success: true, value: 'FAIL' };
  }

  if (normalized.includes('pass')) {
    return { success: true, value: 'PASS' };
  }

  return { success: true, value: 'NEUTRAL' };
}
```

### Error Handling Pattern

All functions return `Result<T, E>` types for type-safe error handling:

```typescript
type Result<T, E> = { success: true; value: T } | { success: false; error: E };
```

This approach:

- Makes errors explicit in function signatures
- Prevents silent failures
- Enables graceful degradation
- Improves testability

### Stateless Design

- No shared mutable state between requests
- Each email analysis is independent
- Caching only for external API responses
- Deterministic outputs for same inputs

---

## Threat Intelligence Integration

### Optional Enrichment

External threat intelligence is optional and runs in parallel:

**VirusTotal**: URL/domain/IP reputation
**AbuseIPDB**: IP abuse confidence scoring
**URLScan.io**: Live URL scanning and screenshots

### Graceful Degradation Strategy

```typescript
// Parallel execution with timeout protection
const results = await Promise.allSettled([
  Promise.race([checkVirusTotal(url), timeout(5000)]),
  Promise.race([checkAbuseIPDB(ip), timeout(5000)]),
  Promise.race([checkURLScan(url), timeout(5000)]),
]);

// Continue analysis even if all APIs fail
const threatIntelRisk = aggregateResults(results);
const finalScore = baseScore + threatIntelRisk;
```

### Benefits

- Analysis never blocked by slow APIs
- System works without API keys
- Caching reduces redundant calls
- Minimal latency impact (2-3s parallel)

---

## LLM-Enhanced Analysis

### Purpose

For borderline cases (risk score 4.0-6.0), the agent can generate natural language explanations using Claude to help users understand the threat assessment.

### Hardening Features

The LLM integration includes production-grade reliability:

**Retry Logic**:

- 3 retry attempts with exponential backoff
- Initial delay: 1 second, max delay: 10 seconds
- Only retries on transient errors (rate limits, timeouts)

**Circuit Breaker**:

- Opens after 5 consecutive failures
- Half-open state after 60 seconds
- Prevents cascade failures during API outages

**Graceful Degradation**:

- Analysis continues without explanation if LLM unavailable
- Risk scoring unaffected by LLM failures
- Users still receive core threat indicators

### When LLM Analysis Runs

```typescript
// Only runs for borderline cases
if (riskScore >= 4.0 && riskScore <= 6.0) {
  const explanation = await generateThreatExplanation(context);
}
```

---

## Performance Characteristics

### Target vs. Actual

| Component               | Target   | Typical  |
| ----------------------- | -------- | -------- |
| Header Validation       | < 100ms  | ~50ms    |
| Content Analysis        | < 500ms  | ~200ms   |
| Threat Intel (parallel) | 2-3s     | 1-2s     |
| Risk Scoring            | < 100ms  | ~30ms    |
| **Total Analysis**      | **< 5s** | **< 1s** |

### Optimization Techniques

1. **Parallel API Calls**: All threat intel queries concurrent
2. **Caching**: 5-minute TTL on external lookups
3. **Atomic Functions**: Simple, fast operations
4. **Early Termination**: Stop analysis on critical findings
5. **Minimal Allocations**: Reuse objects where possible

---

## Testing Approach

### Test Coverage Strategy

- **Unit Tests**: Every atomic function (< 25 lines)
- **Integration Tests**: Pipeline end-to-end
- **Validation Tests**: Real phishing email samples
- **Performance Tests**: Latency and throughput

### Real-World Test Cases

The agent is validated against actual phishing emails:

1. **PayPal/Amazon Impersonation**: Brand spoofing detection
2. **Microsoft 365 Credential Harvesting**: Password phishing
3. **Wire Transfer Fraud (BEC)**: Business email compromise
4. **Typosquatted Domains**: Domain confusion attacks
5. **Malicious Attachments**: File-based threats

### Success Criteria

- ✅ 95%+ true positive rate on known phishing
- ✅ < 5% false positive rate on legitimate email
- ✅ < 5 second analysis time (99th percentile)
- ✅ Zero crashes on malformed input

---

## Logging and Observability

### Log Levels

**Info**: Normal operations (email received, analysis complete)
**Warn**: Suspicious patterns, authentication failures
**Error**: API failures, processing errors
**Security**: All phishing detections with full context

### Structured Logging

All logs use JSON format with correlation IDs:

```json
{
  "level": "security",
  "timestamp": "2025-10-20T12:00:00Z",
  "analysisId": "analysis-abc123",
  "messageId": "<email@example.com>",
  "verdict": "phishing",
  "riskScore": 8.5,
  "severity": "high",
  "indicators": ["spf_fail", "suspicious_url", "brand_impersonation"]
}
```

### Privacy Considerations

- Email content is **never** logged
- Only metadata (sender, subject, headers) recorded
- No PII in logs
- Sanitize all user input before logging

---

## Configuration Philosophy

### Environment-Based Config

All configuration via environment variables:

```bash
# Required
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<your-client-id>
AZURE_CLIENT_SECRET=<your-secret>
PHISHING_MAILBOX_ADDRESS=phishing@yourcompany.com

# Optional with sensible defaults
MAILBOX_CHECK_INTERVAL_MS=60000
THREAT_INTEL_TIMEOUT_MS=5000
RATE_LIMIT_ENABLED=true
MAX_EMAILS_PER_HOUR=100
```

### Design Rationale

- **12-Factor App Compliance**: Config separate from code
- **No Hardcoded Values**: Everything configurable
- **Fail-Fast Validation**: Check config on startup
- **Type Safety**: Zod schema validation on all config

---

## Future Enhancements

### Potential Improvements

**Advanced Content Analysis**:

- Logo/image analysis for visual spoofing
- Attachment deep scanning with hash reputation
- Archive file inspection (nested files)

**User Feedback Loop**:

- Learn from user corrections
- Adjust scoring weights dynamically
- Track false positive/negative rates

**Enterprise Features**:

- Multi-tenant support
- SIEM integration
- Custom risk policies

### Maintaining Philosophy

Future enhancements must preserve core principles:

- ✅ Explainable decisions (no "black box")
- ✅ Fast analysis (< 5 seconds)
- ✅ Low false positives
- ✅ Graceful degradation
- ✅ User-friendly output

---

## References

For implementation details, see:

- **ARCHITECTURE.md** - System design and data flow
- **TECH_STACK.md** - Technology choices and rationale
- **README.md** - Quick start and usage guide
- **CLAUDE.md** - Claude Code project instructions

For operational procedures, see:

- **SECURITY.md** - Credential management
- **roadmap.md** - Feature planning

---

**Document Version**: 2.0
**Last Reviewed**: 2025-11-28
