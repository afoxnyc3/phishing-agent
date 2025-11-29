# Changelog

All notable changes to the phishing-agent project will be documented in this file.

## [0.3.1] - 2025-11-28

### Added
- **Managed Identity Authentication** (Issue #21): Passwordless Azure authentication
  - `DefaultAzureCredential` support for production deployments
  - Automatic fallback to client secret for local development
  - Updated deployment documentation with Managed Identity setup
  - Azure Container Apps system-assigned identity integration
  - Microsoft Graph API permission assignment via CLI
- **Comprehensive Test Coverage**: Security module tests
  - `email-guards.test.ts`: 54 tests for email security guards
  - Extended `email-deduplication.test.ts`: +13 tests (17 → 30)
  - Extended `threat-intel.test.ts`: +14 tests (31 → 45)
  - Total: 661 tests (+81 from v0.3.0)

### Changed
- Updated `DEPLOY_MANUAL.md` with Managed Identity as recommended auth method
- Updated `DEPLOYMENT_PLAN.md` with authentication options table
- Updated `STATUS.md` to v0.3.1 with Phase 4 features
- Test count increased from 580 to 661 tests

### Security
- Removed requirement for `AZURE_CLIENT_SECRET` in production
- Reduced attack surface with passwordless authentication
- Added security guards test coverage for critical email validation

## [0.3.0] - 2025-11-28

### Added
- **Attachment Analysis** (Issue #2): Detect dangerous file attachments
  - Dangerous executable detection (.exe, .bat, .vbs, .scr, .ps1, .cmd)
  - Macro-enabled document flagging (.docm, .xlsm, .pptm)
  - Double extension attack detection (invoice.pdf.exe)
  - Archive file detection (.zip, .rar, .7z, .iso)
  - File size anomaly detection
  - 39 tests for attachment analysis
- **LLM-Enhanced Analysis Hardening** (Issue #4): Production-grade AI analysis
  - Claude 3.5 Haiku integration for borderline cases (score 4-6)
  - Retry logic with exponential backoff (p-retry)
  - Circuit breaker pattern (opossum library)
  - Graceful degradation when LLM unavailable
  - Health check integration
  - 30 tests for LLM analyzer
- **Reporting Dashboard** (Issue #5): Analytics and metrics
  - Daily/weekly phishing metrics aggregation
  - Top phishing senders and domains tracking
  - Severity distribution analysis
  - Indicator breakdown statistics
  - In-memory analytics service
  - 25 tests for reporting dashboard
- Updated documentation (README, ARCHITECTURE, AGENT.md, CLAUDE.md)

### Changed
- Risk scoring now includes attachment analysis (40/30/30 weighting when attachments present)
- Test count increased from 387 to 502 tests
- Documentation updated to v0.3.0

### Fixed
- ESM-compatible mocking for all test files
- Jest configuration for p-retry and other ESM packages

## [0.2.2] - 2025-10-20

### Added
- **Rate Limiter Service**: Prevents email sending abuse with configurable limits
  - Hourly and daily email sending limits (default: 100/hour, 1000/day)
  - Circuit breaker that trips on burst sending (default: 50 emails in 10 minutes)
  - Automatic circuit breaker reset after 1 hour
  - Real-time statistics tracking and logging
- **Email Deduplication Service**: Prevents duplicate analysis replies
  - Content-based hashing to detect duplicate phishing emails
  - Sender cooldown period (default: 24 hours between replies to same sender)
  - Automatic cache expiration and cleanup
- Comprehensive test suite for both services (28 tests total)
- Configuration options via environment variables
- Updated documentation (README.md, .env.example)

### Changed
- Mailbox monitor now integrates rate limiting and deduplication checks
- Email processing skips duplicate content and rate-limited sends
- Health check endpoints now include rate limit and deduplication statistics

### Fixed
- **Critical**: Mass email sending incident prevention (10,000+ emails/day)
- Email reply loops from duplicate processing
- Microsoft 365 sending limit violations

## [0.2.1] - 2025-10-19

### Added
- Docker multi-stage build for production deployment
- Azure Container Apps production environment
- Azure Container Registry integration
- Production documentation (DEPLOYMENT_PLAN.md, DEPLOY_MANUAL.md)
- Comprehensive security guide (SECURITY.md)
- Production health check validation
- End-to-end production testing with real phishing email

### Changed
- Updated README.md with Docker deployment instructions
- Updated all project documentation with production status
- Configured Azure AD permissions for production mailbox access

### Validated
- Production deployment to Azure Container Apps (East US)
- Analysis performance <1 second in production
- Risk assessment accuracy (7.65/10 score with 9 threat indicators)
- Email reply delivery successfully tested

## [0.2.0] - 2025-10-16

### Added
- Core analysis engine (header-validator, content-analyzer, risk-scorer)
- Threat intel integration (VirusTotal, AbuseIPDB, URLScan) with parallel execution
- Mailbox monitoring via Microsoft Graph API (60s polling)
- HTML email reply functionality with risk assessment
- HTTP server with health checks (`/health`, `/ready`)
- Production-ready logging and error handling
- Configuration management with environment variables
- Graceful shutdown handling
- GitHub repository and issues created

### Changed
- Updated architecture to use custom async orchestration with `Promise.allSettled()`
- Moved threat intel from Phase 2 to MVP (Phase 1)

## [0.1.0] - 2025-10-16

### Added
- Project initialization
- Documentation templates (README, ARCHITECTURE, roadmap, decision-log)
- TypeScript configuration with strict mode
- Development environment setup

---

**Format**: This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

**Versioning**: This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
