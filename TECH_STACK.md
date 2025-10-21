# Technology Stack

**Purpose**: This document provides a comprehensive technology inventory for the phishing-agent project, including runtime environment, dependencies, infrastructure, and deployment specifications.

**Last Updated**: 2025-10-20
**Version**: v0.2.2

---

## Runtime Environment

### Core Runtime
- **Node.js**: 18.x (LTS)
- **TypeScript**: 5.3+
- **Target**: ES2022
- **Module System**: CommonJS (CJS)

### Compiler Configuration
- **Strict Mode**: Enabled
- **Source Maps**: Enabled for debugging
- **Output Directory**: `dist/`
- **Declaration Files**: Disabled (runtime only)

---

## Production Dependencies

### Microsoft Graph Integration
```json
"@azure/identity": "^4.0.0"
"@microsoft/microsoft-graph-client": "^3.0.7"
```
**Purpose**: OAuth 2.0 authentication and email operations
**Usage**: Client credentials flow (app-only authentication)
**Permissions**: Mail.Read, Mail.Send, Mail.ReadWrite (Application scope)

### HTTP & Networking
```json
"axios": "^1.6.5"
"express": "^5.0.0"
```
**axios**: External API calls (VirusTotal, AbuseIPDB, URLScan)
**express**: HTTP server for health checks (`/health`, `/ready`)

### Caching
```json
"node-cache": "^5.1.2"
```
**Purpose**: In-memory caching for threat intelligence API responses
**TTL**: 5 minutes (300 seconds)
**Usage**: Avoid rate limits and improve performance

### Logging
```json
"winston": "^3.11.0"
```
**Purpose**: Structured JSON logging
**Levels**: info, warn, error, security
**Format**: JSON with timestamps and correlation IDs
**Transport**: Console (stdout/stderr)

### Runtime Validation
```json
"zod": "^3.22.4"
```
**Purpose**: Runtime schema validation for external data
**Usage**: Environment config, Graph API responses, threat intel APIs
**Benefits**: Type-safe error handling, clear validation messages

---

## Development Dependencies

### TypeScript Tooling
```json
"typescript": "^5.3.3"
"@types/node": "^20.10.6"
"@types/express": "^4.17.21"
"tsx": "^4.7.0"
```
**tsx**: Hot-reload development server (faster than ts-node)

### Testing Framework
```json
"jest": "^29.7.0"
"ts-jest": "^29.1.1"
"@types/jest": "^29.5.11"
```
**Coverage**: 95%+ overall (340 passing tests)
**Strategy**: Unit tests for atomic functions, integration tests for services
**Includes**: Rate limiting tests (63 tests), deduplication tests, core analysis tests

### Code Quality
```json
"eslint": "^8.56.0"
"@typescript-eslint/parser": "^6.18.1"
"@typescript-eslint/eslint-plugin": "^6.18.1"
```
**Rules**: Strict TypeScript linting, no unused variables, consistent formatting

---

## Infrastructure & Deployment

### Container Platform
- **Base Image**: `node:18-alpine`
- **Build Strategy**: Multi-stage Docker build
- **Final Image Size**: 264MB
- **Architecture**: linux/amd64
- **User**: Non-root (`node` user)
- **Health Check**: Native Node.js HTTP check (no curl dependency)

### Azure Services
- **Container Apps**: Serverless container hosting
- **Container Registry**: Private Docker registry (Basic SKU)
- **Azure AD**: OAuth 2.0 identity provider
- **Microsoft Graph**: Email API

### Deployment Configuration
```yaml
# docker-compose.yml
version: '3.8'
services:
  phishing-agent:
    build: .
    env_file: .env
    ports: ["3000:3000"]
    restart: unless-stopped
```

---

## External APIs (Optional)

### Threat Intelligence
```env
# VirusTotal
VIRUSTOTAL_API_KEY=optional
Endpoint: https://www.virustotal.com/api/v3/
Purpose: URL/domain/IP reputation scanning
Rate Limit: 4 req/min (free tier)

# AbuseIPDB
ABUSEIPDB_API_KEY=optional
Endpoint: https://api.abuseipdb.com/api/v2/
Purpose: IP abuse confidence scoring
Rate Limit: 1000 req/day (free tier)

# URLScan.io
URLSCAN_API_KEY=optional
Endpoint: https://urlscan.io/api/v1/
Purpose: URL scanning and screenshot capture
Rate Limit: 100 scans/day (free tier)
```

**Strategy**: Parallel execution with 5-second timeout per API
**Caching**: 5-minute TTL to avoid duplicate lookups
**Graceful Degradation**: System continues if APIs unavailable

---

## Development Tools

### Build System
```bash
npm run build         # Compile TypeScript to JavaScript
npm run dev           # Hot-reload development server
npm run clean         # Remove build artifacts
```

### Testing
```bash
npm test              # Run all tests
npm test -- --watch   # Watch mode
npm test -- --coverage # Coverage report
```

### Code Quality
```bash
npm run lint          # ESLint validation
npm run lint:fix      # Auto-fix linting issues
npm run typecheck     # TypeScript type checking
```

### Docker
```bash
docker build -t phishing-agent:latest .
docker run -d --env-file .env -p 3000:3000 phishing-agent
docker-compose up -d  # Recommended for local development
```

---

## Cloud Deployment Example

### Example Azure Configuration
```
Resource Group: rg-phishing-agent (choose your region)
Location: Choose based on requirements (e.g., East US, West Europe)
Container Registry: <your-registry-name>.azurecr.io
Container App: phishing-agent
Environment: <your-environment-name>
```

**Note**: This is an example for Azure. Adapt for AWS (ECS, Fargate), GCP (Cloud Run), or other providers.

### Compute Specifications
```
Platform: Azure Container Apps (serverless) or equivalent
Auto-scaling: 1-3 replicas (configurable)
Resources per replica: 0.5 vCPU, 1Gi RAM (minimum recommended)
Ingress: External HTTPS (automatic certificates)
Health checks: /health, /ready endpoints
```

### Environment Variables (Production Example)
```env
# Required
AZURE_TENANT_ID=<your-azure-tenant-id>
AZURE_CLIENT_ID=<your-azure-client-id>
AZURE_CLIENT_SECRET=secretref:azure-client-secret  # Stored as secret
PHISHING_MAILBOX_ADDRESS=phishing@yourcompany.com

# Optional (with defaults)
PORT=3000
NODE_ENV=production
MAILBOX_CHECK_INTERVAL_MS=60000
MAILBOX_MONITOR_ENABLED=true
LOG_LEVEL=info

# Rate Limiting (Recommended)
RATE_LIMIT_ENABLED=true
MAX_EMAILS_PER_HOUR=100
MAX_EMAILS_PER_DAY=1000
CIRCUIT_BREAKER_THRESHOLD=50

# Email Deduplication (Recommended)
DEDUPLICATION_ENABLED=true
DEDUPLICATION_TTL_MS=86400000
SENDER_COOLDOWN_MS=86400000
```

### Secrets Management
- **Cloud Provider Secrets**: Store in Azure Key Vault, AWS Secrets Manager, or GCP Secret Manager
- **Container Apps Pattern**: `secretref:<secret-name>`
- **Rotation**: 90-day recommended interval (see SECURITY.md)

---

## Performance Characteristics

### Analysis Pipeline
| Component | Target | Actual (Production) |
|-----------|--------|---------------------|
| Header Validation | <100ms | ~50ms |
| Content Analysis | <500ms | ~200ms |
| Threat Intel (parallel) | 2-3s | 1-2s (with caching) |
| Risk Scoring | <100ms | ~30ms |
| **Total Analysis** | **3-5s** | **<1s** ✅ |

### Mailbox Monitoring
| Metric | Value |
|--------|-------|
| Polling Interval | 60 seconds (configurable) |
| Max Emails per Check | 50 (Graph API limit) |
| Detection Latency | 60 seconds average |

### Resource Usage
| Resource | Development | Production |
|----------|-------------|------------|
| RAM | ~200MB | ~150MB (optimized) |
| CPU (idle) | <5% | <2% |
| CPU (analysis) | 20-30% | 15-20% |
| Disk Space | ~450MB | ~264MB (Docker image) |

---

## Dependencies Graph

```
phishing-agent (root)
├── @azure/identity (Azure AD authentication)
├── @microsoft/microsoft-graph-client (Email operations)
├── axios (External API calls)
├── express (HTTP server)
├── node-cache (Threat intel caching)
├── winston (Structured logging)
└── zod (Runtime validation)

Dev Dependencies:
├── typescript (Compiler)
├── jest + ts-jest (Testing)
├── eslint + @typescript-eslint/* (Linting)
└── tsx (Dev server)
```

---

## Version Control & CI/CD

### Repository
- **Version Control**: Git
- **Hosting**: GitHub (or equivalent)
- **Branch Strategy**: Main branch (direct commits for MVP)
- **Commit Style**: Conventional Commits (`feat:`, `fix:`, `docs:`)

### Deployment Strategy
- **Current**: Manual deployment (Lean Startup approach)
- **Rationale**: Validate MVP before investing in automation
- **Future**: GitHub Actions CI/CD pipeline (see DEPLOYMENT_PLAN.md Phase 2)

---

## Security & Compliance

### Authentication
- **Method**: OAuth 2.0 Client Credentials Flow
- **Provider**: Azure AD
- **Token Lifetime**: 1 hour (automatically refreshed)
- **Permissions**: Application-type (requires admin consent)

### Data Privacy
- **Email Content**: Not logged (only metadata)
- **PII Handling**: Sanitized from structured logs
- **Secrets**: Stored in Azure Container Apps secrets
- **Credential Rotation**: Documented in SECURITY.md

### Vulnerability Management
```bash
npm audit                # Check for known vulnerabilities
npm audit fix            # Auto-fix compatible updates
npm outdated             # Check for outdated packages
```

**Policy**: Monthly security audit, critical patches within 48 hours

---

## Monitoring & Observability

### Logging
- **Format**: JSON (structured)
- **Levels**: info, warn, error, security
- **Correlation IDs**: Track email processing end-to-end
- **Transport**: Azure Container Apps log stream

### Metrics (Planned)
- Emails processed per hour
- Average analysis time
- Phishing detection rate
- False positive rate
- API error rates

### Health Checks
```bash
GET /health
Response: {"status":"healthy","timestamp":"2025-10-20T...","version":"0.2.2"}

GET /ready
Response: {"status":"ready","phishingAgent":true,"mailboxMonitor":true}
```

---

## Cost Breakdown

### Monthly Operational Costs
| Service | SKU | Cost |
|---------|-----|------|
| Azure Container Apps | 1 replica avg, 0.5 vCPU, 1Gi RAM | ~$25-30 |
| Azure Container Registry | Basic | ~$5 |
| Azure AD | Free tier | $0 |
| Microsoft Graph | Included with M365 | $0 |
| **Total** | | **~$30-35/month** |

### API Costs (If Using Paid Tiers)
| Service | Free Tier | Paid Tier |
|---------|-----------|-----------|
| VirusTotal | 4 req/min | $50/month (500 req/day) |
| AbuseIPDB | 1000 req/day | Custom pricing |
| URLScan | 100 scans/day | $100/month (unlimited) |

**Current**: Using free tiers only

---

## Documentation

### Project Documentation
- **README.md** - Quick start and usage guide
- **ARCHITECTURE.md** - System design and data flow
- **AGENT_DESIGN.md** - Design philosophy and methodology
- **STATUS.md** - Current project status
- **roadmap.md** - Feature planning and GitHub issues
- **decision-log.md** - Technical decisions with rationale
- **changelog.md** - Version history

### Deployment Documentation
- **DEPLOYMENT_PLAN.md** - Comprehensive infrastructure roadmap (4 phases)
- **DEPLOY_MANUAL.md** - Step-by-step manual deployment guide
- **SECURITY.md** - Credential management and rotation procedures

### Technical Artifacts (This Document Set)
- **TECH_STACK.md** - Technology inventory (this document)
- **LESSONS_LEARNED.md** - Key insights from MVP development
- **DEV_WORKFLOW.md** - Development processes and conventions
- **EXECUTIVE_SUMMARY.md** - Business-focused project overview

---

## Support & Resources

### Official Documentation
- [Node.js Docs](https://nodejs.org/docs/latest-v18.x/api/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/overview)
- [Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/)

### Community Resources
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)

---

**Document Version**: 1.1
**Last Audit**: 2025-10-20
**Next Review**: 2025-11-20 (monthly review cycle)
