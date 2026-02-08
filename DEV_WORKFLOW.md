# Development Workflow

Development processes, conventions, and best practices for the phishing-agent project.

**Last Updated**: 2025-10-19
**Version**: v0.2.1

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Development Environment Setup](#development-environment-setup)
3. [Development Cycle](#development-cycle)
4. [Code Standards](#code-standards)
5. [Testing Strategy](#testing-strategy)
6. [Git Workflow](#git-workflow)
7. [Deployment Process](#deployment-process)
8. [Debugging](#debugging)
9. [Release Process](#release-process)

---

## Project Structure

### Directory Layout

```
phishing-agent/
├── src/                          # Source code (TypeScript)
│   ├── agents/                   # Core agent logic
│   │   └── phishing-agent.ts     # Main orchestrator (25 lines max)
│   ├── analysis/                 # Analysis modules
│   │   ├── header-validator.ts   # SPF/DKIM/DMARC validation
│   │   ├── content-analyzer.ts   # URL/keyword detection
│   │   └── risk-scorer.ts        # Risk calculation
│   ├── services/                 # External service integrations
│   │   ├── mailbox-monitor.ts    # Graph API polling
│   │   ├── graph-email-parser.ts # Email conversion
│   │   └── threat-intel.ts       # VirusTotal, AbuseIPDB, URLScan
│   ├── lib/                      # Shared utilities
│   │   ├── config.ts             # Environment configuration
│   │   ├── logger.ts             # Winston logging setup
│   │   ├── types.ts              # TypeScript type definitions
│   │   ├── schemas.ts            # Zod validation schemas
│   │   └── email-parser.ts       # Email parsing utilities
│   ├── server.ts                 # Express HTTP server
│   └── index.ts                  # Main entry point
├── dist/                         # Compiled JavaScript (gitignored)
├── coverage/                     # Test coverage reports (gitignored)
├── node_modules/                 # Dependencies (gitignored)
├── docs/                         # Documentation (optional)
├── .env                          # Environment variables (gitignored)
├── .env.example                  # Template for environment variables
├── .gitignore                    # Git ignore patterns
├── .dockerignore                 # Docker build context exclusions
├── Dockerfile                    # Multi-stage Docker build
├── docker-compose.yml            # Local development with Docker
├── package.json                  # NPM dependencies and scripts
├── package-lock.json             # Locked dependency versions
├── tsconfig.json                 # TypeScript configuration
├── jest.config.js                # Jest test configuration
├── eslint.config.js              # ESLint configuration
├── README.md                     # Quick start guide
├── ARCHITECTURE.md               # System design documentation
├── CLAUDE.md                     # Agent behavior specification
├── STATUS.md                     # Project status
├── roadmap.md                    # Feature planning
├── changelog.md                  # Version history
├── decision-log.md               # Technical decisions
├── SECURITY.md                   # Security procedures
├── DEPLOYMENT_PLAN.md            # Infrastructure roadmap
├── DEPLOY_MANUAL.md              # Manual deployment guide
├── TECH_STACK.md                 # Technology inventory
├── LESSONS_LEARNED.md            # Key insights
├── DEV_WORKFLOW.md               # This document
└── EXECUTIVE_SUMMARY.md          # Business overview
```

### File Naming Conventions

- **TypeScript files**: `kebab-case.ts` (e.g., `mailbox-monitor.ts`)
- **Test files**: `*.test.ts` (e.g., `mailbox-monitor.test.ts`)
- **Type files**: `types.ts` (centralized in `src/lib/`)
- **Documentation**: `UPPERCASE.md` or `lowercase.md` (e.g., `README.md`, `roadmap.md`)

---

## Development Environment Setup

### Prerequisites

- **Node.js**: 18.x LTS (check with `node --version`)
- **npm**: 9.x+ (check with `npm --version`)
- **Docker**: 24.x+ (optional, for containerized development)
- **Azure CLI**: 2.x+ (for production deployment)

### Initial Setup

1. **Clone Repository**:

   ```bash
   git clone https://github.com/afoxnyc3/phishing-agent.git
   cd phishing-agent
   ```

2. **Install Dependencies**:

   ```bash
   npm install
   ```

3. **Configure Environment**:

   ```bash
   cp .env.example .env
   # Edit .env with your Azure credentials
   ```

4. **Verify Setup**:
   ```bash
   npm run build      # Should compile without errors
   npm test           # Should pass all tests
   npm run typecheck  # Should have no type errors
   npm run lint       # Should pass linting
   ```

### IDE Configuration

**Recommended**: Visual Studio Code

**Extensions**:

- `ms-vscode.vscode-typescript-next` - TypeScript support
- `dbaeumer.vscode-eslint` - ESLint integration
- `esbenp.prettier-vscode` - Code formatting
- `firsttris.vscode-jest-runner` - Run individual tests

**VS Code Settings** (`.vscode/settings.json`):

```json
{
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "typescript.tsdk": "node_modules/typescript/lib",
  "jest.autoRun": "off"
}
```

---

## Development Cycle

### 1. Start Development Server

```bash
npm run dev
```

**What it does**:

- Compiles TypeScript on the fly (using `tsx`)
- Watches for file changes
- Hot-reloads on save (<500ms)
- Preserves application state during reload

**Output**:

```
info: Phishing Agent initialized successfully
info: HTTP server started on port 3000
info: Mailbox monitor started successfully
```

### 2. Make Changes

**Typical workflow**:

1. Create new function in appropriate module
2. Write unit test first (TDD approach)
3. Implement function (max 25 lines)
4. Run test: `npm test -- mailbox-monitor.test.ts`
5. Verify hot-reload in dev server
6. Commit with conventional commit message

### 3. Run Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- mailbox-monitor.test.ts

# Run tests in watch mode
npm test -- --watch

# Run tests with coverage
npm test -- --coverage

# Run tests matching pattern
npm test -- -t "should validate SPF record"
```

### 4. Build for Production

```bash
npm run build
```

**Output**: `dist/` directory with compiled JavaScript

**Verification**:

```bash
node dist/index.js  # Should start without errors
```

---

## Code Standards

### Function Size Limit: 25 Lines Maximum

**Rationale**: Forces single responsibility, improves testability

**Example**:

```typescript
// ❌ BAD: 50-line function
export function analyzeEmail(email: Email): AnalysisResult {
  // Header validation...
  // Content analysis...
  // Risk scoring...
  // Threat intel...
  // Report generation...
}

// ✅ GOOD: 4 atomic functions (each <25 lines)
export function validateHeaders(headers: EmailHeaders): HeaderResult;
export function analyzeContent(body: string): ContentResult;
export function calculateRisk(results: ValidationResult): number;
export function generateReport(risk: number): AnalysisResult;
```

**Enforcement**: Code review (automated enforcement in ESLint planned)

### File Size Limit: 150 Lines Maximum

**Rationale**: Keeps modules focused and maintainable

**Exceptions**: Auto-generated files, type definitions

### TypeScript Strict Mode

**Configuration** (`tsconfig.json`):

```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "strictPropertyInitialization": true,
    "noImplicitThis": true,
    "alwaysStrict": true
  }
}
```

**Benefits**: Catch type errors at compile time, not runtime

### Error Handling Pattern

**Use `Result<T, E>` type for operations that can fail**:

```typescript
type Result<T, E = Error> = { success: true; value: T } | { success: false; error: E };

// Example usage
export function parseEmailAddress(sender: string | undefined): Result<string, Error> {
  if (!sender || !sender.includes('@')) {
    return { success: false, error: new Error('Invalid email format') };
  }
  const match = sender.match(/<(.+?)>/) || [null, sender];
  return { success: true, value: match[1].toLowerCase() };
}

// Calling code
const result = parseEmailAddress(email.from);
if (!result.success) {
  logger.error('Failed to parse email address', { error: result.error });
  return;
}
const address = result.value; // TypeScript knows this is string
```

**Benefits**: Explicit error handling, no uncaught exceptions

### Naming Conventions

**Variables and Functions**:

- `camelCase` for variables and functions
- `UPPER_SNAKE_CASE` for constants
- `PascalCase` for types and interfaces

**Examples**:

```typescript
const emailAddress = 'user@example.com';        // variable
const MAX_RETRIES = 3;                          // constant
function validateEmail(email: string): boolean  // function
interface EmailHeaders { ... }                  // interface
type AnalysisResult = { ... }                   // type
```

---

## Testing Strategy

### Test Coverage Target: 90-95%

**Current**: 95.82% (277 passing tests)

**Coverage by Module**:

- `analysis/` (header-validator, content-analyzer, risk-scorer): 97-100%
- `services/` (mailbox-monitor, graph-email-parser, threat-intel): 93-97%
- `lib/` (config, logger, types, schemas): 90-95%

### Test File Organization

**Convention**: `<module-name>.test.ts` next to `<module-name>.ts`

**Example**:

```
src/analysis/
├── header-validator.ts
├── header-validator.test.ts
├── content-analyzer.ts
└── content-analyzer.test.ts
```

### Writing Tests

**Template**:

```typescript
import { describe, test, expect } from '@jest/globals';
import { validateSpfRecord } from './header-validator';

describe('validateSpfRecord', () => {
  test('should return PASS for valid SPF record', () => {
    const result = validateSpfRecord('spf=pass');
    expect(result.success).toBe(true);
    expect(result.value).toBe('PASS');
  });

  test('should return FAIL for failed SPF record', () => {
    const result = validateSpfRecord('spf=fail');
    expect(result.success).toBe(true);
    expect(result.value).toBe('FAIL');
  });

  test('should return error for missing SPF header', () => {
    const result = validateSpfRecord(undefined);
    expect(result.success).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
  });
});
```

### Test Naming Convention

**Format**: `should <expected behavior> when <condition>`

**Examples**:

- ✅ `should return PASS for valid SPF record`
- ✅ `should detect suspicious URL with IP address`
- ✅ `should calculate HIGH risk score for multiple failures`
- ❌ `test SPF validation` (too vague)
- ❌ `SPF test` (not descriptive)

### Mocking External Services

**Use Jest mocks for Graph API and threat intel APIs**:

```typescript
import { jest } from '@jest/globals';

jest.mock('@microsoft/microsoft-graph-client', () => ({
  Client: {
    init: jest.fn().mockReturnValue({
      api: jest.fn().mockReturnValue({
        get: jest.fn().mockResolvedValue({ value: [] }),
      }),
    }),
  },
}));
```

### Integration Tests

**Run integration tests with real Azure credentials** (optional):

```bash
# Set INTEGRATION_TESTS=true in .env
npm test -- --testPathPattern=integration
```

---

## Git Workflow

### Branch Strategy

**Current**: Main branch only (MVP phase)

**Future**: Feature branches + pull requests

### Commit Message Convention

**Format**: `<type>: <description>`

**Types**:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or changes
- `refactor:` - Code refactoring (no behavior change)
- `chore:` - Build process, dependency updates
- `perf:` - Performance improvements

**Examples**:

```
feat: add Zod runtime validation for production safety
fix: resolve Docker platform mismatch for Azure deployment
docs: update roadmap with production deployment milestone
test: add comprehensive schema validation tests
refactor: extract email parsing logic to separate module
chore: update dependencies to latest versions
perf: optimize URL extraction with compiled regex
```

**Generated with Claude Code footer** (required):

```
🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

### Pre-Commit Checklist

Before committing, ensure:

- [ ] `npm run build` succeeds
- [ ] `npm test` passes (all tests)
- [ ] `npm run lint` passes (no linting errors)
- [ ] `npm run typecheck` passes (no type errors)
- [ ] All files formatted consistently
- [ ] No console.log statements (use logger instead)
- [ ] No commented-out code
- [ ] Commit message follows convention

### Pushing Changes

```bash
# Stage changes
git add <files>

# Commit with conventional message
git commit -m "feat: add new analysis module"

# Push to remote
git push origin main
```

---

## Deployment Process

### Local Development

**Option 1: Direct Node.js**:

```bash
npm run dev  # Hot-reload development server
```

**Option 2: Docker Compose** (recommended):

```bash
docker-compose up -d    # Start in background
docker-compose logs -f  # View logs
docker-compose down     # Stop and remove
```

### Manual Production Deployment

See **DEPLOY_MANUAL.md** for comprehensive step-by-step guide.

**Quick reference**:

```bash
# 1. Build for linux/amd64
docker buildx build --platform linux/amd64 \
  -t phishingagentacr.azurecr.io/phishing-agent:v0.2.1 \
  . --load

# 2. Push to Azure Container Registry
az acr login --name phishingagentacr
docker push phishingagentacr.azurecr.io/phishing-agent:v0.2.1

# 3. Update Container App
az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --image phishingagentacr.azurecr.io/phishing-agent:v0.2.1
```

### Automated Deployment (Future)

See **DEPLOYMENT_PLAN.md Phase 2** for CI/CD pipeline design.

---

## Debugging

### Local Debugging

**VS Code Launch Configuration** (`.vscode/launch.json`):

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug Phishing Agent",
      "runtimeExecutable": "tsx",
      "runtimeArgs": ["src/index.ts"],
      "skipFiles": ["<node_internals>/**"],
      "envFile": "${workspaceFolder}/.env"
    }
  ]
}
```

**Usage**: Press F5 to start debugging with breakpoints

### Production Debugging

**View live logs**:

```bash
az containerapp logs show \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --follow
```

**SSH into container** (if needed):

```bash
az containerapp exec \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --command /bin/sh
```

**Check environment variables**:

```bash
az containerapp show \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --query properties.configuration.secrets
```

### Common Issues

**Issue**: `Access is denied` error from Graph API

**Solution**:

1. Check Azure AD permissions: `az ad app permission list --id <app-id>`
2. Verify Mail.Read, Mail.Send, Mail.ReadWrite are granted
3. Grant admin consent: `az ad app permission admin-consent --id <app-id>`
4. Restart container: `az containerapp revision restart ...`

**Issue**: Container won't start

**Solution**:

1. Check logs: `az containerapp logs show ...`
2. Verify environment variables are set
3. Check image platform: Should be linux/amd64

**Issue**: Tests failing locally

**Solution**:

1. Delete `node_modules` and `package-lock.json`
2. Run `npm install`
3. Run `npm test -- --clearCache`

---

## Release Process

### Versioning

**Semantic Versioning**: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

**Examples**:

- `v0.1.0` - Initial project setup
- `v0.2.0` - MVP implementation complete
- `v0.2.1` - Production deployment
- `v0.3.0` - Enhanced detection features (future)

### Release Checklist

Before releasing a new version:

1. **Update version** in `package.json`
2. **Update CHANGELOG.md** with release notes
3. **Update README.md** with new features/changes
4. **Run full test suite**: `npm test -- --coverage`
5. **Build production image**: `docker build -t phishing-agent:v0.x.x .`
6. **Test image locally**: `docker run --env-file .env phishing-agent:v0.x.x`
7. **Tag release in git**: `git tag v0.x.x`
8. **Push tag**: `git push origin v0.x.x`
9. **Deploy to production** (see DEPLOY_MANUAL.md)
10. **Verify production health**: `curl https://<prod-url>/health`

### Release Notes Template

```markdown
## [0.x.x] - YYYY-MM-DD

### Added

- New feature description

### Changed

- Modified functionality description

### Fixed

- Bug fix description

### Deprecated

- Feature to be removed in future

### Removed

- Removed feature description

### Security

- Security fix description
```

---

## Code Review Guidelines

### What to Review

- ✅ **Correctness**: Does the code do what it claims?
- ✅ **Tests**: Are there tests? Do they cover edge cases?
- ✅ **Function size**: Are functions <25 lines?
- ✅ **File size**: Are files <150 lines?
- ✅ **Type safety**: No `any` types without justification?
- ✅ **Error handling**: Are errors handled gracefully?
- ✅ **Naming**: Are names clear and descriptive?
- ✅ **Documentation**: Is complex logic documented?

### Review Checklist

- [ ] All tests pass locally
- [ ] New tests added for new functionality
- [ ] Code follows style guide (ESLint passes)
- [ ] No hardcoded secrets or credentials
- [ ] Logging is appropriate (no PII in logs)
- [ ] Performance is acceptable
- [ ] Documentation updated (README, ARCHITECTURE, etc.)

---

## Performance Monitoring

### Key Metrics to Track

**Analysis Performance**:

- Header validation time (<100ms target)
- Content analysis time (<500ms target)
- Threat intel enrichment time (2-3s target)
- Total analysis time (<5s target)

**Mailbox Monitoring**:

- Polling interval (60s configured)
- Emails processed per check
- Failed API calls (should be <1%)

**System Health**:

- Memory usage (<200MB target)
- CPU usage (<20% average)
- Container restart count (should be 0)

### Logging Best Practices

**Use appropriate log levels**:

```typescript
logger.info('Email received', { subject, from }); // Normal operation
logger.warn('SPF validation failed', { domain }); // Suspicious activity
logger.error('Graph API call failed', { error }); // System errors
logger.security('Phishing detected', { score, risk }); // Security events
```

**Include correlation IDs**:

```typescript
const correlationId = uuidv4();
logger.info('Starting email analysis', { correlationId, emailId });
// ... analysis ...
logger.info('Analysis complete', { correlationId, riskScore });
```

---

## Documentation Standards

### Documentation Files

**Required**:

- `README.md` - Quick start guide
- `ARCHITECTURE.md` - System design
- `CLAUDE.md` - Agent behavior spec

**Recommended**:

- `STATUS.md` - Project status
- `roadmap.md` - Feature planning
- `changelog.md` - Version history
- `SECURITY.md` - Security procedures

### Code Documentation

**Use JSDoc comments for complex functions**:

```typescript
/**
 * Calculate risk score based on validation results.
 *
 * Risk scoring formula:
 * - Base score: 0
 * - +2.0 for each authentication failure (SPF, DKIM, DMARC)
 * - +1.5 for each suspicious URL
 * - +2.0 for brand impersonation
 * - +1.0 for urgency keywords
 *
 * @param headerResult - Header validation results
 * @param contentResult - Content analysis results
 * @returns Risk score (0-10 scale)
 */
export function calculateRiskScore(headerResult: HeaderValidationResult, contentResult: ContentAnalysisResult): number {
  // Implementation...
}
```

---

## Useful Commands Reference

### Development

```bash
npm install           # Install dependencies
npm run dev           # Start development server (hot-reload)
npm run build         # Compile TypeScript to JavaScript
npm run clean         # Remove build artifacts
```

### Testing

```bash
npm test              # Run all tests
npm test -- --watch   # Run tests in watch mode
npm test -- --coverage # Run tests with coverage report
npm run test:integration # Run integration tests (requires Azure creds)
```

### Code Quality

```bash
npm run lint          # Run ESLint
npm run lint:fix      # Auto-fix linting issues
npm run typecheck     # Run TypeScript type checking
```

### Docker

```bash
docker build -t phishing-agent:latest .                    # Build image
docker run -d --env-file .env -p 3000:3000 phishing-agent  # Run container
docker-compose up -d                                        # Start services
docker-compose logs -f                                      # View logs
docker-compose down                                         # Stop services
```

### Azure CLI

```bash
az login                                       # Login to Azure
az account show                                # Show current subscription
az containerapp logs show ... --follow         # View live logs
az containerapp revision restart ...           # Restart container
az containerapp update ... --image <new-image> # Update image
```

---

## Support & Resources

### Internal Documentation

- **README.md** - Quick start guide
- **ARCHITECTURE.md** - System design
- **DEPLOYMENT_PLAN.md** - Infrastructure roadmap
- **DEPLOY_MANUAL.md** - Deployment guide
- **SECURITY.md** - Security procedures

### External Resources

- **Node.js Docs**: https://nodejs.org/docs/latest-v18.x/api/
- **TypeScript Handbook**: https://www.typescriptlang.org/docs/
- **Jest Documentation**: https://jestjs.io/docs/getting-started
- **Microsoft Graph API**: https://learn.microsoft.com/en-us/graph/

### Getting Help

- **GitHub Issues**: https://github.com/afoxnyc3/phishing-agent/issues
- **Project Lead**: Alex

---

**Document Version**: 1.0
**Last Updated**: 2025-10-19
**Next Review**: 2025-11-19 (monthly review cycle)
