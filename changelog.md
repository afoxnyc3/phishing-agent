# Changelog

All notable changes to the phishing-agent project will be documented in this file.

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
