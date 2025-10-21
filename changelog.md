# Changelog

All notable changes to the phishing-agent project will be documented in this file.

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
