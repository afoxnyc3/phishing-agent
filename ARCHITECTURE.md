# Phishing Agent Architecture

## System Overview

**Purpose**: Automated phishing email analysis triggered by email forwarding.

**Flow**: User forwards suspicious email → Mailbox monitor detects → Analyze for phishing → Send HTML reply with findings.

**Performance Target**: 2-5 seconds per email analysis, 10 seconds total response time.

---

## Technology Stack

- **Runtime**: Node.js 18+ with TypeScript 5+
- **Email API**: Microsoft Graph API (app-only authentication)
- **HTTP Server**: Express 5 (minimal, health checks only)
- **Logging**: Winston (structured JSON logs)
- **Authentication**: Azure Client Secret Credential
- **Optional Intel**: VirusTotal, AbuseIPDB, URLScan.io

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
**File**: `src/analysis/phishing-agent.ts`

**Responsibilities**:
- Validate email headers (SPF, DKIM, DMARC)
- Analyze content (URLs, keywords, patterns)
- Calculate risk score (0-10)
- Generate threat indicators list
- Return structured analysis result

**Pipeline**:
```
Email → Header Validation → Content Analysis → [Threat Intel Enrichment] → Risk Scoring → Result
```

**Note**: Threat intel enrichment runs in parallel with core analysis for speed.

### 3. Threat Intel Enricher (NEW)
**File**: `src/integrations/threat-intel-enricher.ts`

**Responsibilities**:
- Enrich analysis with external threat intelligence
- Query VirusTotal, AbuseIPDB, URLScan.io in parallel
- Apply 5-second timeout per API
- Cache results (5-min TTL) to avoid rate limits
- Gracefully degrade if APIs unavailable

**Strategy**: Custom async orchestration with `Promise.allSettled()`

**Sub-components**:
- `src/integrations/virustotal-client.ts` - URL/domain/IP reputation
- `src/integrations/abuseipdb-client.ts` - IP abuse scoring
- `src/integrations/urlscan-client.ts` - URL screenshot + analysis

**Parallel Execution**:
```typescript
// All APIs called in parallel with timeout protection
const results = await Promise.allSettled([
  Promise.race([checkVirusTotal(url), timeout(5000)]),
  Promise.race([checkAbuseIPDB(ip), timeout(5000)]),
  Promise.race([checkURLScan(url), timeout(5000)])
]);
// Continue analysis even if some APIs fail
```

**Rate Limiting**: 10 req/s per API using `p-limit` library

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
- `aggregateRiskScore(headerRisk, contentRisk)` - Combine scores
- `determineSeverity(riskScore)` - Map to LOW/MEDIUM/HIGH/CRITICAL

### 6. Email Sender
**File**: `src/services/email-sender.ts`

**Responsibilities**:
- Format HTML email with analysis results
- Send via Graph API
- Handle delivery failures gracefully

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
│ Email Parser         │
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
│ Email Sender         │
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
