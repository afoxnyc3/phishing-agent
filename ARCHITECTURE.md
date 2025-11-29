# Phishing Agent Architecture

**Purpose**: This document provides a comprehensive technical overview of the phishing agent system architecture, components, and data flow.

**Last Updated**: 2025-11-29
**Version**: v0.3.1

---

## System Overview

**Purpose**: Automated phishing email analysis triggered by email forwarding.

**Flow**: User forwards suspicious email → Mailbox monitor detects → Analyze for phishing → Send HTML reply with findings.

**Performance Target**: < 1 second typical analysis time, 5 seconds maximum.

---

## Technology Stack

- **Runtime**: Node.js 18+ with TypeScript 5+
- **Email API**: Microsoft Graph API (app-only authentication)
- **HTTP Server**: Express 5 (minimal, health checks only)
- **Logging**: Winston (structured JSON logs)
- **Authentication**: Azure Managed Identity (production) or Client Secret (development)
- **Optional Intel**: VirusTotal, AbuseIPDB, URLScan.io
- **Optional LLM**: Anthropic Claude (for borderline case explanations)

---

## Core Components

### 1. Mailbox Monitor
**File**: `src/services/mailbox-monitor.ts`

**Responsibilities**:
- Poll mailbox every 60 seconds
- Query Graph API for new emails since last check
- Pass each email to phishing analyzer
- Send HTML reply to original sender

**API Calls**:
- `GET /users/{mailbox}/messages` - Retrieve new emails
- `POST /users/{mailbox}/sendMail` - Send analysis reply

### 2. Phishing Analyzer
**File**: `src/agents/phishing-agent.ts`

**Responsibilities**:
- Orchestrate complete analysis pipeline
- Validate email headers (SPF, DKIM, DMARC)
- Analyze content (URLs, keywords, patterns)
- Enrich with threat intelligence (optional)
- Calculate risk score (0-10)
- Generate threat indicators list
- Return structured analysis result

**Pipeline**:
```
Email → Header Validation → Content Analysis → Attachment Analysis →
[Threat Intel Enrichment] → Risk Scoring → [LLM Explanation] → Result
```

**Note**: Threat intel enrichment runs in parallel with core analysis for speed. LLM explanation only runs for borderline cases (risk 4.0-6.0).

### 3. Threat Intel Enricher
**Files**:
- `src/services/threat-intel.ts` - Main orchestrator service
- `src/services/threat-intel-clients.ts` - API client implementations

**Responsibilities**:
- Enrich analysis with external threat intelligence
- Query VirusTotal, AbuseIPDB in parallel via dedicated client classes
- Each client has built-in retry logic (p-retry) and circuit breaker (opossum)
- Cache results (5-min TTL) to avoid rate limits
- Gracefully degrade if APIs unavailable

**Architecture**: Service + Client pattern for separation of concerns

**Client Features**:
- **VirusTotalClient**: URL reputation checking with retry + circuit breaker
- **AbuseIPDBClient**: IP abuse scoring with retry + circuit breaker

**Caching**: 5-minute TTL using `node-cache` (avoid duplicate lookups)

### 4. Header Validator
**File**: `src/analysis/header-validator.ts`

**Atomic Functions**:
- `validateSpfRecord(spfHeader)` - Check SPF result
- `validateDkimRecord(dkimHeader)` - Check DKIM signature
- `validateDmarcRecord(dmarcHeader)` - Check DMARC policy
- `extractAuthenticationResults(headers)` - Parse auth headers

### 4. Content Analyzer
**File**: `src/analysis/content-analyzer.ts`

**Atomic Functions**:
- `extractUrls(body)` - Find all URLs using regex
- `detectSuspiciousUrls(urls)` - Identify IP addresses, typosquatting
- `detectBrandImpersonation(body, domain)` - Match brand keywords
- `detectUrgencyKeywords(body)` - Find pressure tactics

### 5. Risk Scorer
**File**: `src/analysis/risk-scorer.ts`

**Atomic Functions**:
- `calculateHeaderRisk(headerResult)` - Score auth failures
- `calculateContentRisk(contentResult)` - Score suspicious patterns
- `calculateAttachmentRisk(attachmentResult)` - Score dangerous files
- `aggregateRiskScore(header, content, attachment)` - Weighted combination
- `determineSeverity(riskScore)` - Map to LOW/MEDIUM/HIGH/CRITICAL

**Weighting**:
- With attachments: Header (40%) + Content (30%) + Attachment (30%)
- Without attachments: Header (60%) + Content (40%)

### 6. Attachment Analyzer
**File**: `src/analysis/attachment-analyzer.ts`

**Responsibilities**:
- Detect dangerous executable extensions (.exe, .bat, .vbs, .scr, etc.)
- Flag macro-enabled documents (.docm, .xlsm, .pptm)
- Identify double extension tricks (invoice.pdf.exe)
- Detect archive files that may hide malware (.zip, .rar, .iso)
- Flag suspicious file sizes (too small or too large)

**Risk Levels**:
- CRITICAL: Executables, double extensions
- HIGH: Macro-enabled documents
- MEDIUM: Archives, suspicious sizes

### 7. LLM Analyzer
**File**: `src/services/llm-analyzer.ts`

**Responsibilities**:
- Generate natural language threat explanations
- Only runs for borderline cases (risk score 4.0-6.0)
- Retry logic with exponential backoff (3 attempts)
- Circuit breaker (opens after 5 failures, resets after 60s)
- Graceful degradation (analysis continues without explanation)

**Configuration**:
```typescript
ANTHROPIC_API_KEY=your-key  // Optional - enables LLM explanations
LLM_MODEL=claude-sonnet-4-20250514  // Model to use
LLM_MAX_TOKENS=500  // Response length limit
```

### 8. Reporting Dashboard
**File**: `src/services/reporting-dashboard.ts`

**Responsibilities**:
- Aggregate phishing analysis metrics
- Track top phishing senders and domains
- Calculate severity distribution and trends
- Provide indicator type breakdown

**Key Methods**:
- `recordAnalysis(result, sender)` - Store analysis result
- `generateReport(days)` - Generate dashboard report
- `getTopSenders(limit)` - Get top phishing senders
- `getSeverityTrend(days)` - Get severity over time

### 9. Graph Email Parser
**File**: `src/services/graph-email-parser.ts`

**Responsibilities**:
- Convert Microsoft Graph API email objects to analysis request format
- Extract headers from `internetMessageHeaders` array
- Parse URLs from email body
- Handle attachments metadata

---

## Data Flow

```
┌──────────────────┐
│ User forwards    │
│ suspicious email │
└────────┬─────────┘
         │
         v
┌──────────────────────┐
│ Mailbox Monitor      │ (polls every 60s)
│ Graph API query      │
└────────┬─────────────┘
         │
         v
┌──────────────────────┐
│ Graph Email Parser   │
│ Extract headers/body │
└────────┬─────────────┘
         │
         v
┌──────────────────────────────────────┐
│ Phishing Analyzer                    │
│ ┌────────────────┐  ┌──────────────┐│
│ │ Header         │  │ Threat Intel ││
│ │ Validation     │  │ Enrichment   ││
│ │ (SPF/DKIM)     │  │ (parallel)   ││
│ └────────┬───────┘  └─────┬────────┘│
│          │                 │         │
│          v                 v         │
│      ┌──────────────────────────┐   │
│      │ Content Analysis         │   │
│      │ (URLs, keywords)         │   │
│      └──────────┬───────────────┘   │
│                 │                    │
│                 v                    │
│      ┌──────────────────────────┐   │
│      │ Risk Scoring             │   │
│      │ (aggregate all data)     │   │
│      └──────────────────────────┘   │
└──────────────┬───────────────────────┘
               │
               v
┌──────────────────────┐
│ Mailbox Monitor      │
│ Format HTML reply    │
│ Send via Graph API   │
└──────────────────────┘
```

**Note**: Threat intel APIs (VirusTotal, AbuseIPDB, URLScan) run in parallel to minimize latency.

---

## API Endpoints

### Health Check
```
GET /health
Response: { "status": "healthy", "timestamp": "..." }
```

### Readiness Check
```
GET /ready
Response: {
  "status": "ready",
  "mailboxMonitor": { "isRunning": true, "lastCheckTime": "..." }
}
```

---

## Configuration

### Environment Variables

**Required**:
- `AZURE_TENANT_ID` - Azure AD tenant
- `AZURE_CLIENT_ID` - App registration client ID
- `AZURE_CLIENT_SECRET` - App registration secret
- `PHISHING_MAILBOX_ADDRESS` - Monitored mailbox (e.g., phishing@company.com)

**Optional**:
- `MAILBOX_CHECK_INTERVAL_MS` - Polling frequency (default: 60000)
- `PORT` - HTTP server port (default: 3000)
- `NODE_ENV` - Environment (development/production)

**Threat Intel** (optional):
- `VIRUSTOTAL_API_KEY` - URL/domain/IP reputation
- `ABUSEIPDB_API_KEY` - IP abuse scoring
- `URLSCAN_API_KEY` - URL scanning

### Azure Permissions

App registration requires:
- `Mail.Read` - Read emails from monitored mailbox
- `Mail.Send` - Send analysis replies
- `Mail.ReadWrite` - Mark emails as read (optional)

---

## Error Handling

### Graceful Degradation
- **Graph API timeout**: Skip email, log error, continue polling
- **Analysis failure**: Send error reply to user
- **Email send failure**: Log error, mark email as failed

### Retry Strategy
- **Graph API 429**: Exponential backoff (1s, 2s, 4s)
- **Transient failures**: Retry up to 3 times
- **Permanent failures**: Log and skip

---

## Performance Characteristics

**Mailbox Polling**:
- Interval: 60 seconds (configurable)
- Max emails per check: 50 (Graph API limit)

**Analysis Performance**:
- Header validation: <100ms
- Content analysis: <500ms
- Threat intel enrichment: 2-3 seconds (parallel, with 5s timeout)
- Risk scoring: <100ms
- Total: 3-5 seconds average (up to 8 seconds with threat intel)

**Email Reply**:
- HTML formatting: <100ms
- Graph API send: 1-2 seconds
- Total response time: 10 seconds average

---

## Security Considerations

### Data Privacy
- No email content logged (only metadata)
- Sanitize all user input
- No PII in structured logs

### Authentication
- App-only authentication (no user context)
- Client secret stored in environment variables
- Rotate secrets every 90 days

### Rate Limiting
- Graph API: 10,000 requests/10 min per app
- Threat intel APIs: Varies by provider (use caching)

---

## Deployment

### Local Development
```bash
npm install
cp .env.example .env
# Edit .env with credentials
npm run dev
```

### Production (Docker)
```bash
docker build -t phishing-agent .
docker run -d --env-file .env -p 3000:3000 phishing-agent
```

### Azure Container Apps
```bash
az containerapp create \
  --name phishing-agent \
  --resource-group rg-security \
  --environment container-env \
  --image phishing-agent:latest \
  --env-vars-file .env
```

---

## Example Cloud Deployment

This section provides an example of deploying to Azure Container Apps. Adapt to your cloud provider (AWS, GCP, etc.) as needed.

### Azure Container Apps Deployment Example

**Platform**: Azure Container Apps (serverless container hosting)

**Example Configuration**:
- **Resource Group**: `rg-phishing-agent` (choose your region)
- **Container Registry**: `<your-registry-name>.azurecr.io`
- **Container App**: `phishing-agent`
- **Environment**: `cae-phishing-agent`
- **Production URL**: `https://<your-app-name>.<region>.azurecontainerapps.io/`

**Compute Specifications**:
- **Platform**: Azure Container Apps (serverless)
- **Container Image**: node:18-alpine (multi-stage build)
- **Image Size**: ~264MB
- **Architecture**: linux/amd64
- **Auto-scaling**: 1-3 replicas (configurable)
- **Resources per replica**: 0.5 vCPU, 1Gi RAM (minimum recommended)
- **Ingress**: External HTTPS (automatic certificates)

**Authentication & Permissions**:
- **Azure AD App ID**: `<your-azure-app-id>`
- **Auth Method**: Client credentials flow (app-only)
- **Permissions Required**: Mail.Read, Mail.Send, Mail.ReadWrite (Application scope)
- **Monitored Mailbox**: `phishing@yourcompany.com`
- **Secrets Management**: Azure Container Apps secrets (or Azure Key Vault)

**Example Resource Topology**:
```
┌─────────────────────────────────────────────────────────┐
│ Azure Container Apps Environment                        │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Container App (phishing-agent)                   │  │
│  │                                                   │  │
│  │  ┌─────────────────────────────────────────┐    │  │
│  │  │ Container (phishing-agent:v0.2.2)       │    │  │
│  │  │                                          │    │  │
│  │  │ • Node.js 18 Runtime                    │    │  │
│  │  │ • Mailbox Monitor (60s polling)         │    │  │
│  │  │ • Phishing Analyzer                     │    │  │
│  │  │ • HTTP Server (health checks)           │    │  │
│  │  │                                          │    │  │
│  │  │ Environment Variables:                  │    │  │
│  │  │ • AZURE_TENANT_ID=<your-tenant>         │    │  │
│  │  │ • AZURE_CLIENT_ID=<your-client>         │    │  │
│  │  │ • AZURE_CLIENT_SECRET (secretref)       │    │  │
│  │  │ • PHISHING_MAILBOX_ADDRESS              │    │  │
│  │  │ • PORT=3000                             │    │  │
│  │  └─────────────────────────────────────────┘    │  │
│  │                                                   │  │
│  │  Ingress: HTTPS (automatic certificates)         │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
                        │
                        │ Pull Images
                        ↓
┌─────────────────────────────────────────────────────────┐
│ Container Registry                                       │
│ • Image: phishing-agent:v0.2.2 (~264MB)                 │
│ • Image: phishing-agent:latest                          │
└─────────────────────────────────────────────────────────┘
                        │
                        │ OAuth 2.0 (Client Credentials)
                        ↓
┌─────────────────────────────────────────────────────────┐
│ Microsoft Graph API                                      │
│ • Read emails from phishing@yourcompany.com             │
│ • Send HTML reply emails                                │
└─────────────────────────────────────────────────────────┘
```

### Estimated Cloud Costs

**Azure Example** (Costs vary by region and usage):
- Container Apps: ~$25-30/month (1 replica average, 0.5 vCPU, 1Gi RAM)
- Container Registry Basic: ~$5/month
- **Estimated Total**: ~$30-35/month

**Note**: Actual costs depend on:
- Number of replicas (auto-scaling)
- Region selected
- Network egress
- API call volume

### Deployment Approach

**Manual Deployment** (MVP validation):
- Fastest path to production
- Validate with real users first
- Invest in automation after validation

**CI/CD Automation** (Post-validation):
- GitHub Actions or Azure DevOps
- Automated testing and deployment
- See DEPLOYMENT_PLAN.md for comprehensive guides

### Validation Checklist

After deployment, verify:
- ✅ Health endpoint responds: `curl https://your-url.com/health`
- ✅ Readiness check passes: `curl https://your-url.com/ready`
- ✅ Mailbox polling working (check logs)
- ✅ End-to-end test with sample email
- ✅ Analysis performance meets targets
- ✅ Email replies delivered successfully

---

## Monitoring

### Logs
- **Info**: Email received, analysis completed
- **Warn**: Authentication failures, suspicious patterns
- **Error**: API failures, processing errors
- **Security**: Phishing detections with risk scores

### Metrics
- Emails processed per minute
- Average analysis time
- Phishing detection rate
- False positive rate

### Health Checks
- `/health` - Basic server health
- `/ready` - Mailbox monitor status

---

## Email Loop Prevention Architecture

**Added**: October 20, 2025 (Post-incident)
**Incident Report**: See [AZURE_EMAIL_LOOP_INCIDENT.md](./AZURE_EMAIL_LOOP_INCIDENT.md)

### Critical Incident Background

On October 20, 2025, the phishing agent entered an email loop, sending **10,000 emails in 24 hours** by replying to its own analysis emails. This section documents the multi-layer defense architecture implemented to prevent future incidents.

### Multi-Layer Defense System

**Defense in Depth Philosophy**: Never rely on a single safeguard. Email loop prevention requires 5+ layers:

```
┌────────────────────────────────────────────────────┐
│ Layer 1: Email Loop Detection (CRITICAL)          │
│ File: src/services/mailbox-monitor.ts:148-156     │
│ Function: shouldProcessEmail()                     │
│ Purpose: Prevent agent from replying to itself    │
└────────────────┬───────────────────────────────────┘
                 ↓ (If Layer 1 fails)
┌────────────────────────────────────────────────────┐
│ Layer 2: Rate Limiting (CRITICAL)                 │
│ File: src/services/rate-limiter.ts                │
│ Limits: 100/hour, 1000/day                        │
│ Purpose: Cap total emails sent per time period    │
└────────────────┬───────────────────────────────────┘
                 ↓ (If Layers 1-2 fail)
┌────────────────────────────────────────────────────┐
│ Layer 3: Circuit Breaker (HIGH)                   │
│ File: src/services/rate-limiter.ts:68-72          │
│ Trigger: 50 emails in 10 minutes                  │
│ Purpose: Emergency stop for burst sending         │
└────────────────┬───────────────────────────────────┘
                 ↓ (If Layers 1-3 fail)
┌────────────────────────────────────────────────────┐
│ Layer 4: Email Deduplication (MEDIUM)             │
│ File: src/services/email-deduplication.ts         │
│ Method: SHA-256 content hashing                   │
│ Purpose: Prevent re-analyzing same email          │
└────────────────┬───────────────────────────────────┘
                 ↓ (If Layers 1-4 fail)
┌────────────────────────────────────────────────────┐
│ Layer 5: Sender Cooldown (MEDIUM)                 │
│ File: src/services/email-deduplication.ts:59-67   │
│ Cooldown: 24 hours per sender                     │
│ Purpose: Max 1 reply per sender per day           │
└────────────────────────────────────────────────────┘
```

### Layer 1: Email Loop Detection

**Implementation**:
```typescript
// src/services/mailbox-monitor.ts:148-156
private shouldProcessEmail(email: any): boolean {
  const fromAddress = EmailParser.extractEmail(email.from.emailAddress.address);

  // Prevent email loops: Don't reply to our own address
  if (fromAddress.toLowerCase() === this.config.mailboxAddress.toLowerCase()) {
    securityLogger.warn('Email loop detected: ignoring email from our own address', {
      from: fromAddress,
      subject: email.subject,
    });
    return false;
  }

  return true;
}
```

**Purpose**: Primary defense against email loops
**Detection**: Checks if `from` address matches agent's mailbox address
**Action**: Ignore email (do not process or reply)

**Why It Failed Initially**: This check was not implemented in the original deployment.

### Layer 2: Rate Limiting

**Implementation**:
```typescript
// src/services/rate-limiter.ts
export class RateLimiter {
  canSendEmail(): { allowed: boolean; reason?: string } {
    this.cleanOldTimestamps();

    // Check hourly limit
    const hourlyCount = this.getCountInWindow(60 * 60 * 1000);
    if (hourlyCount >= this.config.maxEmailsPerHour) {
      return {
        allowed: false,
        reason: `Hourly limit reached (${hourlyCount}/${this.config.maxEmailsPerHour})`
      };
    }

    // Check daily limit
    const dailyCount = this.getCountInWindow(24 * 60 * 60 * 1000);
    if (dailyCount >= this.config.maxEmailsPerDay) {
      return {
        allowed: false,
        reason: `Daily limit reached (${dailyCount}/${this.config.maxEmailsPerDay})`
      };
    }

    return { allowed: true };
  }
}
```

**Configuration**:
```bash
# Default limits
MAX_EMAILS_PER_HOUR=100
MAX_EMAILS_PER_DAY=1000
```

**Purpose**: Damage control if email loop detection fails
**Algorithm**: Sliding window (maintains timestamp array)
**Memory**: Auto-cleanup (removes timestamps older than 24 hours)

**Impact During Incident**: Not implemented initially. Would have capped loop at 100 emails/hour vs 10,000/day.

### Layer 3: Circuit Breaker

**Implementation**:
```typescript
// src/services/rate-limiter.ts:68-72
canSendEmail(): { allowed: boolean; reason?: string } {
  // ... hourly/daily checks ...

  // Check for burst (circuit breaker trigger)
  const burstCount = this.getCountInWindow(this.config.circuitBreakerWindowMs);
  if (burstCount >= this.config.circuitBreakerThreshold) {
    this.tripCircuitBreaker();  // Auto-reset in 1 hour
    return { allowed: false, reason: 'Circuit breaker tripped due to burst sending' };
  }

  return { allowed: true };
}

private tripCircuitBreaker(): void {
  this.circuitBreakerTripped = true;
  this.circuitBreakerResetTime = Date.now() + 60 * 60 * 1000;  // Reset in 1 hour

  securityLogger.error('Circuit breaker tripped!', {
    resetTime: new Date(this.circuitBreakerResetTime).toISOString(),
    reason: 'Burst sending detected',
  });
}
```

**Configuration**:
```bash
CIRCUIT_BREAKER_THRESHOLD=50    # 50 emails
CIRCUIT_BREAKER_WINDOW_MS=600000  # 10 minutes
```

**Purpose**: Emergency stop for rapid email loops
**Detection**: 50 emails in 10 minutes = abnormal burst
**Action**: Block all sending for 1 hour (auto-reset)
**Alert**: Security log error + metric counter

**Why Circuit Breaker vs Rate Limiting**:
- Rate limiting: Gradual enforcement (100/hour spread evenly)
- Circuit breaker: Immediate shutdown on burst pattern
- Example: 50 emails in 5 min → Circuit breaker trips (doesn't wait for hourly limit)

### Layer 4: Email Deduplication

**Implementation**:
```typescript
// src/services/email-deduplication.ts
private hashEmailContent(subject: string, body: string): string {
  // Use first 1000 chars of body to avoid hashing entire email
  const content = `${subject}||${body.substring(0, 1000)}`;
  return crypto
    .createHash('sha256')
    .update(content.toLowerCase().trim())
    .digest('hex');
}

shouldProcess(sender: string, subject: string, body: string): { allowed: boolean; reason?: string } {
  const contentHash = this.hashEmailContent(subject, body);

  if (this.isDuplicateContent(contentHash)) {
    return {
      allowed: false,
      reason: `Duplicate email already processed (hash: ${contentHash.substring(0, 8)})`
    };
  }

  return { allowed: true };
}
```

**Configuration**:
```bash
DEDUPLICATION_ENABLED=true
DEDUPLICATION_TTL_MS=86400000  # 24 hours
```

**Purpose**: Prevent re-analyzing identical emails
**Algorithm**: SHA-256 hash of `subject + first 1000 chars of body`
**Cache**: In-memory Map with TTL (auto-cleanup every 5 minutes)

**Why It Helps with Loops**:
- Agent's analysis replies have same content
- Hash matches → Email ignored
- Prevents processing same loop iteration multiple times

### Layer 5: Sender Cooldown

**Implementation**:
```typescript
// src/services/email-deduplication.ts:59-67
shouldProcess(sender: string, subject: string, body: string): { allowed: boolean; reason?: string } {
  // ... content hash check ...

  // Check sender cooldown
  if (this.isSenderInCooldown(sender)) {
    const lastReply = this.senderLastReply.get(sender.toLowerCase());
    const nextAllowed = new Date(lastReply + this.config.senderCooldownMs);
    return {
      allowed: false,
      reason: `Sender in cooldown period (next allowed: ${nextAllowed.toISOString()})`
    };
  }

  return { allowed: true };
}
```

**Configuration**:
```bash
SENDER_COOLDOWN_MS=86400000  # 24 hours
```

**Purpose**: Max 1 reply per sender per day
**Storage**: In-memory Map (sender email → last reply timestamp)

**Why It Helps with Loops**:
- Even if agent replies to itself once, cooldown prevents 2nd reply
- Limits damage to 1 email per sender per 24 hours

---

## Email Processing Flow with Prevention

### Complete Email Processing Pipeline

```
┌─────────────────────────────────┐
│ Mailbox Monitor (60s polling)  │
└────────────┬────────────────────┘
             ↓
┌─────────────────────────────────┐
│ New Email Detected              │
└────────────┬────────────────────┘
             ↓
     ┌───────────────┐
     │ Layer 1 Check │ ← Email Loop Detection
     │ Self-reply?   │
     └───┬───────────┘
         │ No
         ↓
     ┌───────────────┐
     │ Layer 4 Check │ ← Email Deduplication
     │ Duplicate?    │
     └───┬───────────┘
         │ No
         ↓
     ┌───────────────┐
     │ Layer 5 Check │ ← Sender Cooldown
     │ Cooldown?     │
     └───┬───────────┘
         │ No
         ↓
┌─────────────────────────────────┐
│ Analyze Email                   │
│ (Headers + Content + TI)        │
└────────────┬────────────────────┘
             ↓
     ┌───────────────┐
     │ Layer 2 Check │ ← Rate Limiting
     │ Hourly/Daily? │
     └───┬───────────┘
         │ Allowed
         ↓
     ┌───────────────┐
     │ Layer 3 Check │ ← Circuit Breaker
     │ Burst?        │
     └───┬───────────┘
         │ Allowed
         ↓
┌─────────────────────────────────┐
│ Send Reply                      │
│ Record timestamp                │
│ Update deduplication cache      │
└─────────────────────────────────┘
```

### Error Handling Strategy

**Graceful Degradation**:
- If email loop detected → Log warning + ignore email
- If rate limit exceeded → Log info + skip reply
- If circuit breaker tripped → Log error + alert admins
- If deduplication cache full → Continue processing (fail open)

**No Silent Failures**:
- Every blocked email logged with reason
- Metrics tracked for monitoring
- Alerts triggered on critical events

---

## Configuration

### Environment Variables (Email Loop Prevention)

```bash
# Layer 1: Email Loop Detection (always enabled)
PHISHING_MAILBOX_ADDRESS=phishing@yourcompany.com  # Agent's address

# Layer 2: Rate Limiting
RATE_LIMIT_ENABLED=true
MAX_EMAILS_PER_HOUR=100
MAX_EMAILS_PER_DAY=1000

# Layer 3: Circuit Breaker
CIRCUIT_BREAKER_THRESHOLD=50
CIRCUIT_BREAKER_WINDOW_MS=600000  # 10 minutes

# Layer 4: Email Deduplication
DEDUPLICATION_ENABLED=true
DEDUPLICATION_TTL_MS=86400000  # 24 hours

# Layer 5: Sender Cooldown
SENDER_COOLDOWN_MS=86400000  # 24 hours
```

### Recommended Settings by Environment

**Development**:
```bash
MAX_EMAILS_PER_HOUR=10
MAX_EMAILS_PER_DAY=50
CIRCUIT_BREAKER_THRESHOLD=5
```

**Staging**:
```bash
MAX_EMAILS_PER_HOUR=50
MAX_EMAILS_PER_DAY=200
CIRCUIT_BREAKER_THRESHOLD=25
```

**Production**:
```bash
MAX_EMAILS_PER_HOUR=100
MAX_EMAILS_PER_DAY=1000
CIRCUIT_BREAKER_THRESHOLD=50
```

---

## Testing

### Email Loop Prevention Tests

**Test Suite**: 106 tests added post-incident

**Categories**:
1. **Email Loop Simulation** (15 tests)
   - Self-reply detection
   - Bounce message handling
   - Subject chain detection

2. **Rate Limiter** (63 tests)
   - Hourly limit enforcement
   - Daily limit enforcement
   - Circuit breaker triggering
   - Sliding window algorithm

3. **Email Deduplication** (28 tests)
   - Content hash generation
   - Duplicate detection
   - Sender cooldown
   - Cache expiration

**Critical Test**:
```typescript
// tests/integration/email-loop.test.ts
describe('Email Loop Prevention', () => {
  it('should prevent infinite loop when agent replies to itself', async () => {
    const emailAgent = new EmailAgent({ address: 'agent@company.com' });

    // Step 1: User sends initial email
    await emailAgent.processEmail({ from: 'user@company.com', ... });
    expect(emailAgent.getSentEmailCount()).toBe(1);

    // Step 2: Simulate agent receiving its own reply
    await emailAgent.processEmail({ from: 'agent@company.com', ... });

    // ✅ ASSERT: Agent should NOT reply to itself
    expect(emailAgent.getSentEmailCount()).toBe(1);  // Still 1 (no new reply)
  });
});
```

---

## Monitoring & Alerting

### Metrics (Email Loop Prevention)

```typescript
interface EmailLoopMetrics {
  selfRepliesDetected: number;      // Layer 1 hits
  rateLimitHits: number;            // Layer 2 hits
  circuitBreakerTrips: number;      // Layer 3 activations
  duplicatesDetected: number;       // Layer 4 hits
  senderCooldownHits: number;       // Layer 5 hits
}
```

### Critical Alerts

**Self-Reply Detected** (CRITICAL):
```
Trigger: selfRepliesDetected > 0
Action: Immediate investigation required
Message: "Email loop detected! Agent is replying to itself."
```

**Circuit Breaker Tripped** (CRITICAL):
```
Trigger: circuitBreakerTrips > 0
Action: Immediate investigation required
Message: "Circuit breaker tripped! Burst sending detected."
```

**Rate Limit Approaching** (WARNING):
```
Trigger: rateLimitHits > 90
Action: Monitor for email loop
Message: "Rate limit almost exceeded (90/100)"
```

---

## Incident Response

### If Email Loop Detected

**Step 1: Emergency Stop**
```bash
# Azure Container Apps
az containerapp stop --name phishing-agent --resource-group rg-phishing-agent

# Docker
docker stop phishing-agent
```

**Step 2: Assess Damage**
```bash
# Check sent email count
grep "Email sent" logs.txt | wc -l

# Check for self-reply pattern
grep "from.*phishing@yourcompany.com" logs.txt
```

**Step 3: Review Logs**
```bash
# Find when loop started
grep "Email loop detected" logs.txt | head -1

# Check which layer failed
grep -E "shouldProcessEmail|RateLimiter|CircuitBreaker" logs.txt
```

**Step 4: Fix & Redeploy**
```bash
# Verify all layers enabled
npm test -- email-loop

# Deploy with conservative limits
export MAX_EMAILS_PER_HOUR=10
npm run deploy
```

---

## References

- **Incident Report**: [AZURE_EMAIL_LOOP_INCIDENT.md](./AZURE_EMAIL_LOOP_INCIDENT.md)
- **Lessons Learned**: [LESSONS_LEARNED.md](./LESSONS_LEARNED.md)
- **Prevention Guide**: [EMAIL_LOOP_PREVENTION.md](./EMAIL_LOOP_PREVENTION.md)
- **Testing**: `tests/integration/email-loop.test.ts`

---

**Document Version**: 1.2 (Updated with threat-intel split)
**Last Updated**: November 29, 2025
