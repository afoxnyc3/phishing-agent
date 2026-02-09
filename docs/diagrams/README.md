# Architecture Diagrams

Visual diagrams of the Phishing Agent system architecture and email processing workflow.

## System Architecture

High-level component diagram showing all system modules and their connections.

![System Architecture](system-architecture.svg)

**Components shown:**

- **Email Ingestion** -- Webhook endpoint, subscription manager, mail monitor, notification queue
- **Guard Layers** -- Self-sender detection, message ID dedup, content dedup, auto-responder filter, sender allowlist
- **Analysis Pipeline** -- Header validation, content analysis, attachment analysis, threat intel enrichment, risk scoring, LLM explanation
- **External Services** -- Microsoft Graph API, VirusTotal, AbuseIPDB, Anthropic Claude
- **Infrastructure** -- Express HTTP server, Redis cache, Winston logger, correlation tracking

## Email Processing Workflow

Detailed flowchart from email arrival through guard checks, analysis, and reply.

![Email Processing Workflow](email-processing-workflow.svg)

**Flow highlights:**

- Dual ingestion: webhook push (real-time) or timer poll (fallback)
- 5 guard layers filter before analysis runs
- Header, content, and attachment analysis run sequentially; threat intel enrichment runs in parallel
- LLM explanation only triggers for borderline scores (4.0-6.0)
- Rate limiter and circuit breaker protect reply sending
