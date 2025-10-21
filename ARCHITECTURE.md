# Phishing Agent Architecture

**Purpose**: This document provides a comprehensive technical overview of the phishing agent system architecture, components, and data flow.

**Last Updated**: 2025-10-20
**Version**: v0.2.2

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
Email → Header Validation → Content Analysis → [Threat Intel Enrichment] → Risk Scoring → Result
```

**Note**: Threat intel enrichment runs in parallel with core analysis for speed.

### 3. Threat Intel Enricher
**File**: `src/services/threat-intel.ts`

**Responsibilities**:
- Enrich analysis with external threat intelligence
- Query VirusTotal, AbuseIPDB, URLScan.io in parallel
- Apply 5-second timeout per API
- Cache results (5-min TTL) to avoid rate limits
- Gracefully degrade if APIs unavailable

**Strategy**: Custom async orchestration with `Promise.allSettled()`

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

### 6. Graph Email Parser
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
