# Phishing Agent

Email-triggered phishing analysis agent with automated risk assessment replies.

**Version**: v0.2.2
**Status**: Production-Ready MVP with Rate Limiting & Deduplication

## Overview

**Purpose**: Monitor a designated email inbox → Analyze forwarded suspicious emails → Send risk assessment replies.

**Flow**: User forwards email to monitored mailbox → Agent analyzes headers & content → User receives HTML reply with findings within seconds.

**Tech Stack**: TypeScript + Node.js + Microsoft Graph API + Zod validation + Winston logging + Rate limiting

---

## Features

- **Automated Monitoring**: Poll mailbox every 60 seconds via Microsoft Graph API
- **Fast Analysis**: < 1 second typical phishing detection using rule-based engine
- **Clear Results**: HTML email replies with color-coded risk assessment
- **Threat Indicators**: SPF/DKIM/DMARC validation, suspicious URL detection, brand impersonation
- **Optional Intel**: VirusTotal, AbuseIPDB, URLScan.io integration
- **Runtime Validation**: Zod schema validation for all external API responses
- **Rate Limiting**: Prevent email sending abuse with configurable hourly/daily limits and circuit breaker
- **Deduplication**: Prevent duplicate replies for same phishing email with content hashing and sender cooldown
- **Atomic Code**: Max 25 lines per function, max 150 lines per file

---

## Quick Start

### Prerequisites

- Node.js 18+
- Microsoft 365 mailbox for monitoring
- Azure AD app registration (Mail.Read, Mail.Send permissions)

### Installation

```bash
git clone <repository-url>
cd phishing-agent
npm install
cp .env.example .env
# Edit .env with your Azure credentials
npm run build
npm start
```

### Development

```bash
npm run dev  # Hot reload with tsx
```

---

## Docker Deployment

### Quick Start with Docker

**Option 1: Docker Run**
```bash
# Build image
docker build -t phishing-agent:latest .

# Run container
docker run -d \
  --name phishing-agent \
  --env-file .env \
  -p 3000:3000 \
  phishing-agent:latest

# View logs
docker logs -f phishing-agent

# Stop container
docker stop phishing-agent && docker rm phishing-agent
```

**Option 2: Docker Compose** (Recommended for local development)
```bash
# Start service
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps

# Stop service
docker-compose down
```

### Docker Image Details

- **Base Image**: `node:18-alpine`
- **Size**: ~264MB
- **Architecture**: Multi-stage build (builder + production)
- **Security**: Runs as non-root user (`node`)
- **Health Check**: Integrated `/health` endpoint monitoring

### Environment Variables

All environment variables must be provided at runtime:

```bash
# Required
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-client-id
AZURE_CLIENT_SECRET=your-app-secret
PHISHING_MAILBOX_ADDRESS=phishing@company.com

# Optional (with defaults)
PORT=3000
NODE_ENV=production
MAILBOX_CHECK_INTERVAL_MS=60000
MAILBOX_MONITOR_ENABLED=true
```

Use `--env-file .env` with Docker or `env_file: .env` in docker-compose.yml.

### Health Checks

The container includes built-in health checks:

```bash
# Check health endpoint
curl http://localhost:3000/health

# Check readiness endpoint
curl http://localhost:3000/ready
```

**Health Check Configuration:**
- Interval: 30 seconds
- Timeout: 10 seconds
- Start period: 40 seconds (allows for initialization)
- Retries: 3

### Production Deployment

For production deployments to Azure Container Apps, AWS ECS, or Kubernetes, see [DEPLOYMENT_PLAN.md](./DEPLOYMENT_PLAN.md) for comprehensive infrastructure setup guides.

---

## Configuration

### Required Environment Variables

```env
# Azure Configuration
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-client-id
AZURE_CLIENT_SECRET=your-app-secret

# Mailbox Configuration
PHISHING_MAILBOX_ADDRESS=phishing@company.com
MAILBOX_CHECK_INTERVAL_MS=60000

# Server
PORT=3000
NODE_ENV=development
```

### Optional Threat Intelligence

```env
VIRUSTOTAL_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key
URLSCAN_API_KEY=your-key
```

### Rate Limiting & Deduplication

Prevent email sending abuse and duplicate replies:

```env
# Rate Limiting (prevents mass email incidents)
RATE_LIMIT_ENABLED=true
MAX_EMAILS_PER_HOUR=100          # Maximum outbound emails per hour
MAX_EMAILS_PER_DAY=1000          # Maximum outbound emails per day
CIRCUIT_BREAKER_THRESHOLD=50     # Trip breaker if this many emails sent in window
CIRCUIT_BREAKER_WINDOW_MS=600000 # Circuit breaker window (10 minutes)

# Email Deduplication (prevents duplicate replies)
DEDUPLICATION_ENABLED=true
DEDUPLICATION_TTL_MS=86400000    # How long to remember processed emails (24 hours)
SENDER_COOLDOWN_MS=86400000      # Min time between replies to same sender (24 hours)
```

**How it works:**
- **Content Deduplication**: Same phishing email forwarded by 1000 users = only 1 reply sent
- **Sender Cooldown**: Each user can only receive 1 reply per 24 hours
- **Rate Limiting**: Hard caps at 100 emails/hour and 1000 emails/day
- **Circuit Breaker**: Auto-stops sending if 50 emails sent in 10 minutes (resets after 1 hour)

### Azure AD Permissions

App registration requires:
- `Mail.Read` - Read monitored mailbox
- `Mail.Send` - Send analysis replies
- `Mail.ReadWrite` - Mark emails as read (optional)

**Setup**: Azure Portal → App Registrations → New Registration → API Permissions → Grant Admin Consent

---

## Usage

### How It Works

1. **User forwards suspicious email** to monitored mailbox (e.g., `phishing@yourcompany.com`)
2. **Mailbox monitor** detects new email (polls every 60s)
3. **Analysis engine** evaluates headers + content (SPF, DKIM, DMARC, URLs, keywords)
4. **Risk scorer** calculates threat level (0-10 scale)
5. **Rate limiter** checks sending limits and deduplication
6. **Email sender** replies with HTML-formatted findings
7. **User receives analysis** within seconds

### Example Analysis Reply

```
Subject: Re: URGENT: Account Suspended - Analysis Results

━━━━━━━━━━━━━━━━━━━━━━
PHISHING ANALYSIS RESULTS
━━━━━━━━━━━━━━━━━━━━━━

Risk Assessment:
┌──────────────┬────────────┐
│ Risk Score   │ 8.5/10     │
│ Severity     │ HIGH       │
│ Confidence   │ 95%        │
└──────────────┴────────────┘

Threat Indicators Found:
• SPF authentication failed (HIGH)
• DKIM signature failed (HIGH)
• Suspicious URL with IP address (CRITICAL)
• PayPal brand impersonation detected (HIGH)
• Urgency keywords: "suspended", "verify now" (MEDIUM)

Recommended Actions:
✓ Do NOT click any links in this email
✓ Do NOT provide credentials or personal information
✓ Report to your security team
✓ Delete this email immediately
```

---

## API Endpoints

### Health Check

```bash
GET /health

Response:
{
  "status": "healthy",
  "timestamp": "2025-10-20T12:00:00Z",
  "version": "0.2.2"
}
```

### Readiness Check

```bash
GET /ready

Response:
{
  "status": "ready",
  "mailboxMonitor": {
    "isRunning": true,
    "lastCheckTime": "2025-10-20T12:00:00Z",
    "mailboxAddress": "phishing@yourcompany.com"
  }
}
```

---

## Architecture

### Core Components

```
src/
├── agents/
│   └── phishing-agent.ts      # Main orchestrator
├── analysis/
│   ├── header-validator.ts    # SPF/DKIM/DMARC
│   ├── content-analyzer.ts    # URLs, keywords
│   └── risk-scorer.ts         # Risk calculation
├── services/
│   ├── mailbox-monitor.ts     # Graph API polling
│   ├── graph-email-parser.ts  # Email conversion
│   └── threat-intel.ts        # VirusTotal, AbuseIPDB, URLScan
├── lib/
│   ├── config.ts
│   ├── logger.ts
│   ├── types.ts
│   └── email-parser.ts
├── server.ts                   # Express HTTP server
└── index.ts                    # Main entry point
```

### Data Flow

```
Email received → Parse headers/body → Validate authentication →
Analyze content → Calculate risk → Format HTML reply → Send to user
```

For detailed architecture, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Development Guidelines

### Code Quality Standards

- **Functions**: Max 25 lines, single responsibility
- **Files**: Max 150 lines
- **Style**: Stateless, deterministic, type-safe
- **Error Handling**: Use `Result<T, E>` pattern

### Testing

```bash
npm test              # Run all tests
npm test -- --watch   # Watch mode
npm test -- --coverage # Coverage report
```

**Target**: 90%+ test coverage for all code.

### Example Atomic Function

```typescript
export function validateSpfRecord(spfHeader: string | undefined): Result<string, Error> {
  if (!spfHeader) {
    return { success: false, error: new Error('No SPF header found') };
  }
  if (spfHeader.toLowerCase().includes('fail')) {
    return { success: true, value: 'FAIL' };
  }
  return { success: true, value: 'PASS' };
}
```

---

## Roadmap

### v0.2.2 (Current - Production Ready)
- [x] Project structure and documentation
- [x] Core analysis engine (header-validator, content-analyzer, risk-scorer)
- [x] Mailbox monitoring via Microsoft Graph API
- [x] HTML email reply functionality
- [x] Threat intel integration (VirusTotal, AbuseIPDB, URLScan)
- [x] Zod runtime validation for external APIs
- [x] Rate limiting (hourly/daily caps, circuit breaker)
- [x] Email deduplication (content hashing, sender cooldown)
- [x] Health checks and logging
- [x] Docker containerization
- [x] Testing framework (Jest, 95%+ coverage, 340 tests)

### v0.3.0 (Enhanced Detection - Planned)
- [ ] Brand impersonation detection (Issue #7)
- [ ] Attachment analysis (Issue #8)
- [ ] Cloud deployment automation (CI/CD pipeline)

### v0.4.0 (Advanced Features - Future)
- [ ] Machine learning model (Issue #14)
- [ ] LLM-enhanced analysis (Issue #15)
- [ ] Reporting dashboard (Issue #16)

For complete roadmap and GitHub issues, see [roadmap.md](./roadmap.md).

---

## Documentation

### Core Documentation
- **[AGENT_DESIGN.md](./AGENT_DESIGN.md)** - Design philosophy and methodology
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System design and data flow
- **[STATUS.md](./STATUS.md)** - Current project status
- **[roadmap.md](./roadmap.md)** - Feature planning and roadmap

### Technical Documentation
- **[TECH_STACK.md](./TECH_STACK.md)** - Technology inventory
- **[SECURITY.md](./SECURITY.md)** - Credential management guide
- **[changelog.md](./changelog.md)** - Version history
- **[decision-log.md](./decision-log.md)** - Technical decisions with rationale

### Deployment Documentation
- **[DEPLOYMENT_PLAN.md](./DEPLOYMENT_PLAN.md)** - Infrastructure roadmap
- **[DEPLOY_MANUAL.md](./DEPLOY_MANUAL.md)** - Step-by-step deployment guide

---

## License

MIT License - see LICENSE file for details.

---

## Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Documentation**: See project documentation files for detailed guides
- **Security**: Report vulnerabilities privately via GitHub Security Advisories
- **Contributing**: See CONTRIBUTING.md for guidelines (if available)
