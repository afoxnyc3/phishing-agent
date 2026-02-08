# Claude Code Project Instructions

This file provides Claude Code with project-specific context and guidelines.

## Project Overview

Phishing Agent: An email-triggered phishing analysis agent that monitors a mailbox, analyzes forwarded suspicious emails, and sends HTML risk assessment replies.

## Key Documentation

Before making changes, review:

- **[AGENT.md](./AGENT.md)** - Design philosophy, risk scoring methodology, pipeline architecture
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System components, data flow, technical details

## Code Quality Standards

### Function Size

- **Maximum 25 lines** per function (excluding blank lines and comments)
- **Maximum 200 lines** per file
- Single responsibility per function
- Extract helper functions when approaching limits

### Style Guidelines

- **Stateless design**: Each email analyzed independently
- **Atomic operations**: Simple, focused functions
- **Type safety**: Use TypeScript strict mode, avoid `any`
- **Error handling**: Use `Result<T, E>` pattern or explicit error types

### Example Pattern

```typescript
// Good: Single responsibility, under 25 lines
private static calculateHeaderScore(result: HeaderValidationResult): number {
  let score = 0;
  if (!result.spfResult.isAuthentic) {
    score += result.spfResult.status === 'fail' ? 3 : 1.5;
  }
  if (!result.dkimResult.isAuthentic) {
    score += result.dkimResult.status === 'fail' ? 3 : 1.5;
  }
  return Math.min(score, 10);
}
```

## Testing Requirements

### Jest ESM Configuration

This project uses Jest with ESM modules. Use this pattern for mocking:

```typescript
import { describe, it, expect, jest } from '@jest/globals';

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { MyClass } = await import('./my-class.js');
```

### Test Coverage

- Target: 90%+ coverage
- Every atomic function should have unit tests
- Test edge cases and error conditions

## Key Patterns

### Risk Scoring

Risk scores are 0-10, calculated with weighted aggregation:

- **With attachments**: Header (40%) + Content (30%) + Attachment (30%)
- **Without attachments**: Header (60%) + Content (40%)

### Severity Thresholds

```typescript
PHISHING_THRESHOLD = 5.0; // Score >= 5.0 = phishing
CRITICAL_THRESHOLD = 8.0;
HIGH_THRESHOLD = 6.0;
MEDIUM_THRESHOLD = 3.0;
```

### Graceful Degradation

External services (threat intel APIs, LLM) are optional. Analysis continues without them:

- Use `Promise.allSettled()` for parallel API calls
- Return default values on failure
- Log warnings but don't throw

## File Organization

```
src/
├── agents/         # Main orchestrator (phishing-agent.ts)
├── analysis/       # Detection modules:
│   ├── content-analyzer.ts      # Content analysis orchestrator
│   ├── url-analyzer.ts          # URL/link mismatch detection
│   ├── social-engineering-detector.ts  # Keyword detection
│   ├── brand-detector.ts        # Brand impersonation
│   ├── header-validator.ts      # SPF/DKIM/DMARC
│   ├── attachment-analyzer.ts   # File type detection
│   └── risk-scorer.ts           # Risk calculation
├── services/       # External integrations:
│   ├── threat-intel.ts         # Orchestrates threat intel lookups
│   ├── threat-intel-clients.ts # VirusTotal, AbuseIPDB client classes
│   ├── rate-limiter.ts         # In-memory rate limiting
│   ├── redis-rate-limiter.ts   # Redis-backed rate limiting
│   └── ...                     # Graph API, LLM, etc.
├── lib/            # Config, types, schemas, cache providers
├── server.ts       # Express HTTP server
└── index.ts        # Entry point
```

## NPM Scripts

| Script                      | Description                                        |
| --------------------------- | -------------------------------------------------- |
| `dev`                       | Start dev server with hot reload                   |
| `build`                     | Compile TypeScript to dist/                        |
| `start`                     | Run compiled app                                   |
| `test`                      | Run all tests                                      |
| `test:unit`                 | Run unit tests only                                |
| `test:integration`          | Run integration tests only                         |
| `test:watch`                | Run tests in watch mode                            |
| `test:coverage`             | Run tests with coverage report                     |
| `lint` / `lint:fix`         | ESLint check / auto-fix                            |
| `format` / `format:check`   | Prettier write / check                             |
| `type-check`                | TypeScript compiler check                          |
| `validate`                  | Run all checks (type-check + lint + format + test) |
| `docker:up` / `docker:down` | Start/stop Docker Compose                          |
| `status`                    | Check running service health                       |

## ESLint Rules

Key enforced rules:

- `max-lines: 200` - File length limit
- `max-lines-per-function: 50` - Function length (ESLint setting, aim for 25)
- `complexity: 15` - Cyclomatic complexity limit
- `@typescript-eslint/no-explicit-any` - No `any` types

## Commit Guidelines

When asked to commit:

1. Use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`
2. Reference issues: `Closes #N`
3. Include co-author footer for Claude Code
