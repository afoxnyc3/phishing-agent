# Phishing Agent Roadmap

This roadmap tracks current status, upcoming features, and future enhancements for the phishing-agent project.

---

## Current Status: v0.1.0 (Project Initialization)

**Completion**: 20%

- [x] Project structure created
- [x] Documentation templates
- [x] TypeScript configuration
- [ ] Core analysis engine
- [ ] Mailbox monitoring service
- [ ] Email reply functionality
- [ ] Testing framework
- [ ] GitHub repository setup

---

## Phase 1: Core Functionality (MVP)

**Target**: v0.2.0
**Estimated Duration**: 2-3 weeks

### Features

#### Issue #1: Core Analysis Engine
**Status**: Not Started
**Priority**: P0 (Blocker)

Implement the phishing analysis pipeline:
- Header validator (SPF, DKIM, DMARC)
- Content analyzer (URLs, keywords, patterns)
- Risk scorer (0-10 scale with severity mapping)
- Threat indicator aggregation

**Acceptance Criteria**:
- [ ] All functions <25 lines
- [ ] All files <150 lines
- [ ] 90%+ test coverage
- [ ] Analysis completes in <5 seconds

#### Issue #2: Mailbox Monitor Service
**Status**: Not Started
**Priority**: P0 (Blocker)

Monitor designated mailbox for new emails:
- Graph API integration (app-only auth)
- 60-second polling loop
- Email parsing and extraction
- Error handling and retry logic

**Acceptance Criteria**:
- [ ] Polls mailbox every 60 seconds
- [ ] Handles up to 50 emails per check
- [ ] Graceful error recovery
- [ ] Health check endpoint

#### Issue #3: Email Reply Functionality
**Status**: Not Started
**Priority**: P0 (Blocker)

Send HTML-formatted analysis results:
- HTML email template with risk assessment
- Color-coded severity badges
- Threat indicators list
- Recommended actions

**Acceptance Criteria**:
- [ ] HTML rendering works in major email clients
- [ ] Mobile-responsive design
- [ ] Reply sent within 10 seconds of analysis
- [ ] Handles delivery failures gracefully

#### Issue #4: Configuration Management
**Status**: Not Started
**Priority**: P1 (High)

Simple environment-based configuration:
- Load from .env file
- Validate required variables on startup
- Type-safe configuration access
- Secure secret handling

**Acceptance Criteria**:
- [ ] All config in .env.example documented
- [ ] Fails fast on missing required vars
- [ ] No secrets in logs

#### Issue #5: Logging & Monitoring
**Status**: Not Started
**Priority**: P1 (High)

Structured logging for observability:
- Winston logger with JSON format
- Log levels (info, warn, error, security)
- Correlation IDs for request tracing
- Health check endpoints

**Acceptance Criteria**:
- [ ] All critical events logged
- [ ] No PII in logs
- [ ] Metrics tracked (emails processed, phishing detected)

---

## Phase 2: Enhanced Detection (Post-MVP)

**Target**: v0.3.0
**Estimated Duration**: 2-3 weeks

### Features

#### Issue #6: Threat Intel Integration
**Status**: Not Started
**Priority**: P2 (Medium)

Optional external reputation checks:
- VirusTotal URL/domain scanning
- AbuseIPDB IP reputation
- URLScan.io screenshot capture
- Caching to avoid rate limits

**Acceptance Criteria**:
- [ ] Works with and without API keys
- [ ] Graceful degradation if APIs unavailable
- [ ] 5-minute cache TTL
- [ ] Max 3 retries on failure

#### Issue #7: Brand Impersonation Detection
**Status**: Not Started
**Priority**: P2 (Medium)

Detect common brand spoofing:
- PayPal, Amazon, Microsoft, Apple
- Bank impersonation (Chase, Bank of America, Wells Fargo)
- Typosquatting detection (paypa1.com, micros0ft.com)
- Logo/image analysis (optional)

**Acceptance Criteria**:
- [ ] Detects top 20 impersonated brands
- [ ] Identifies typosquatting patterns
- [ ] <100ms analysis time

#### Issue #8: Attachment Analysis
**Status**: Not Started
**Priority**: P2 (Medium)

Basic attachment risk assessment:
- File type validation (exe, scr, bat, vbs → high risk)
- Macro-enabled documents (docm, xlsm → medium risk)
- Suspicious filenames (invoice.pdf.exe)
- File size anomalies

**Acceptance Criteria**:
- [ ] Detects dangerous file extensions
- [ ] Flags macro-enabled documents
- [ ] Analyzes filename patterns

---

## Phase 3: Advanced Features (Future)

**Target**: v0.4.0+
**Estimated Duration**: TBD

### Potential Features

#### Issue #9: Machine Learning Model
**Status**: Backlog
**Priority**: P3 (Low)

Train custom phishing detection model:
- Supervised learning on labeled dataset
- Feature extraction from headers/content
- Model serving via REST API
- Periodic retraining pipeline

**Considerations**:
- Requires large labeled dataset
- Infrastructure for model training/serving
- May not improve much over rule-based

#### Issue #10: LLM-Enhanced Analysis (Optional)
**Status**: Backlog
**Priority**: P3 (Low)

Optional Claude API integration for edge cases:
- Complex social engineering detection
- Contextual risk assessment
- Natural language explanations
- Only trigger for borderline cases (score 4-6)

**Considerations**:
- Adds latency (5-10s)
- Costs $0.01-0.05 per analysis
- May be overkill for most emails

#### Issue #11: Reporting Dashboard
**Status**: Backlog
**Priority**: P3 (Low)

Web dashboard for analytics:
- Daily/weekly phishing metrics
- Top senders/domains flagged
- False positive rate tracking
- User feedback trends

---

## Maintenance & Operations

### Ongoing Tasks

- **Security Updates**: Monthly dependency audits
- **Documentation**: Update as features added
- **Testing**: Maintain 90%+ coverage
- **Performance**: Monitor analysis times, optimize bottlenecks
- **False Positive Reduction**: Tune risk scoring based on feedback

---

## Version History

- **v0.1.0** (2025-10-16): Project initialization
- **v0.2.0** (Planned): Core MVP functionality
- **v0.3.0** (Planned): Enhanced detection
- **v0.4.0** (Future): Advanced features

---

**Note**: All issues should be created in GitHub with labels (feature, enhancement, bug) and linked to this roadmap.
