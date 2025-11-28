# Email Loop Prevention: Best Practices Guide

**Purpose**: Comprehensive guide for preventing email loops in automated email agents
**Audience**: Engineers building email-triggered automation systems
**Last Updated**: October 22, 2025
**Based on**: Real production incident (October 20, 2025)

---

## Table of Contents

1. [What is an Email Loop?](#what-is-an-email-loop)
2. [Why Email Loops Happen](#why-email-loops-happen)
3. [Multi-Layer Defense Strategy](#multi-layer-defense-strategy)
4. [Implementation Patterns](#implementation-patterns)
5. [Testing Strategies](#testing-strategies)
6. [Monitoring & Alerting](#monitoring--alerting)
7. [Recovery Procedures](#recovery-procedures)

---

## What is an Email Loop?

### Definition

An **email loop** occurs when an automated email agent replies to its own emails, creating an infinite chain of messages.

### Example Email Loop

```
Step 1: User forwards phishing email → agent@company.com
Step 2: Agent analyzes email → Sends reply from agent@company.com
Step 3: Agent polls mailbox → Finds its own reply as "new email"
Step 4: Agent analyzes its own reply → Sends another reply
Step 5: REPEAT STEPS 3-4 INFINITELY ♾️
```

###Subject Line Evolution

```
Original:    "Suspicious email from PayPal"
1st reply:   "Re: Suspicious email from PayPal"
2nd reply:   "Re: Re: Suspicious email from PayPal"
3rd reply:   "Re: Re: Re: Suspicious email from PayPal"
...
100th reply: "Re: Re: Re: Re: Re: Re: Re: Re: ... (100 times)"
```

### Real-World Impact

**Our Incident (October 20, 2025)**:
- **10,000 emails** sent in 24 hours
- **Microsoft 365 security alert** triggered
- **4 hours** to detect and resolve
- **$0 cost** (Azure/Graph API within limits)
- **Internal mailbox only** (no customer impact)

**Worst-Case Scenarios**:
- Millions of emails sent to customers
- Email provider account suspended
- IP address blacklisted
- Reputational damage
- Legal liability (spam laws)

---

## Why Email Loops Happen

### Root Cause: Self-Reply Detection Failure

All email loops share the same root cause:

```typescript
// ❌ VULNERABLE CODE
async function processIncomingEmail(email: Email) {
  // No check if email is from the agent itself
  const analysis = await analyzeEmail(email);
  await sendReply(email.from, analysis);  // ← If email.from is the agent, loop begins
}
```

### Common Scenarios

#### Scenario 1: Direct Self-Reply
```
Agent address: agent@company.com
Incoming email from: agent@company.com
Action: Agent replies to itself
```

#### Scenario 2: Bounce Message Loop
```
Agent sends reply → Email bounces → Bounce notification arrives
Agent analyzes bounce → Sends reply to mailer-daemon
Mailer-daemon sends another bounce → LOOP
```

#### Scenario 3: Forwarding Loop
```
Agent sends reply to user@company.com
User has auto-forward rule → Forwards to agent@company.com
Agent analyzes forwarded email → Sends reply
Auto-forward triggers again → LOOP
```

#### Scenario 4: "Re: Re: Re:" Chain
```
Agent replies with subject "Re: Original subject"
Agent polls mailbox → Finds "Re: Original subject"
Agent doesn't detect it's a reply to its own message → Replies again
Subject becomes "Re: Re: Original subject" → LOOP
```

---

## Multi-Layer Defense Strategy

### Defense in Depth Philosophy

**Never rely on a single safeguard**. Email loops require **5+ layers of protection**:

```
┌─────────────────────────────────────────────────────┐
│ Layer 1: Email Loop Detection (Self-Reply Check)   │ ← PRIMARY
└──────────────────┬──────────────────────────────────┘
                   ↓ (If Layer 1 fails)
┌─────────────────────────────────────────────────────┐
│ Layer 2: Bounce/NDR Detection (mailer-daemon)      │ ← SECONDARY
└──────────────────┬──────────────────────────────────┘
                   ↓ (If Layers 1-2 fail)
┌─────────────────────────────────────────────────────┐
│ Layer 3: Subject Chain Detection (Re: Re: Re:)     │ ← TERTIARY
└──────────────────┬──────────────────────────────────┘
                   ↓ (If Layers 1-3 fail)
┌─────────────────────────────────────────────────────┐
│ Layer 4: Rate Limiting (100/hour, 1000/day)        │ ← DAMAGE CONTROL
└──────────────────┬──────────────────────────────────┘
                   ↓ (If Layers 1-4 fail)
┌─────────────────────────────────────────────────────┐
│ Layer 5: Circuit Breaker (50 emails/10 min)        │ ← EMERGENCY STOP
└─────────────────────────────────────────────────────┘
```

**Principle**: Each layer assumes previous layers failed.

---

## Implementation Patterns

### Layer 1: Self-Reply Detection (CRITICAL)

**Purpose**: Prevent agent from replying to its own emails

**Implementation**:
```typescript
function shouldProcessEmail(email: Email, agentAddress: string): boolean {
  const fromAddress = extractEmailAddress(email.from);

  // Check 1: Exact match
  if (fromAddress.toLowerCase() === agentAddress.toLowerCase()) {
    logger.warn('Email loop detected: self-reply', { from: fromAddress });
    return false;
  }

  // Check 2: Domain match (for multiple agent addresses)
  const fromDomain = fromAddress.split('@')[1];
  const agentDomain = agentAddress.split('@')[1];

  if (fromDomain === agentDomain && fromAddress.startsWith('agent-')) {
    logger.warn('Email loop detected: same domain agent', { from: fromAddress });
    return false;
  }

  return true;
}
```

**Edge Cases to Handle**:
```typescript
// Case 1: Multiple agent addresses
const agentAddresses = [
  'phishing@company.com',
  'security@company.com',
  'analyzer@company.com'
];

if (agentAddresses.includes(fromAddress.toLowerCase())) {
  return false;
}

// Case 2: Case-insensitive matching
if (fromAddress.toLowerCase() === agentAddress.toLowerCase()) {
  return false;
}

// Case 3: Address with display name
// "Phishing Agent <phishing@company.com>"
const cleanedFrom = extractEmailAddress(email.from);  // → phishing@company.com
```

### Layer 2: Bounce/NDR Detection

**Purpose**: Prevent loops with email delivery failure notifications

**Implementation**:
```typescript
function isBounceMessage(email: Email): boolean {
  const from = email.from.toLowerCase();

  // Common bounce senders
  const bounceSenders = [
    'mailer-daemon',
    'postmaster',
    'noreply',
    'no-reply',
    'bounce',
    'undeliverable',
    'delivery-failure',
    'mdaemon',
  ];

  if (bounceSenders.some(sender => from.includes(sender))) {
    logger.info('Bounce message detected', { from: email.from });
    return true;
  }

  // Check subject for bounce indicators
  const subject = email.subject.toLowerCase();
  const bounceKeywords = [
    'undeliverable',
    'delivery failed',
    'returned mail',
    'failure notice',
    'delivery status notification',
  ];

  if (bounceKeywords.some(keyword => subject.includes(keyword))) {
    logger.info('Bounce detected in subject', { subject: email.subject });
    return true;
  }

  return false;
}
```

**Why Bounces Create Loops**:
```
Agent sends to invalid@example.com
↓
Mail server sends bounce to agent@company.com
↓
Agent analyzes bounce message
↓
Agent tries to reply to mailer-daemon@mailserver.com
↓
Another bounce sent to agent@company.com
↓
LOOP
```

### Layer 3: Subject Chain Detection

**Purpose**: Detect "Re: Re: Re:" chains that indicate potential loops

**Implementation**:
```typescript
function isSubjectChain(email: Email, maxDepth: number = 3): boolean {
  const subject = email.subject;

  // Count "Re:" occurrences
  const reCount = (subject.match(/Re:/gi) || []).length;

  if (reCount > maxDepth) {
    logger.warn('Subject chain detected', {
      subject,
      reCount,
      maxDepth,
    });
    return true;
  }

  // Check for "Fwd:" combined with "Re:"
  const fwdCount = (subject.match(/Fwd:/gi) || []).length;
  if (reCount + fwdCount > maxDepth) {
    logger.warn('Combined Re:/Fwd: chain detected', {
      subject,
      totalCount: reCount + fwdCount,
    });
    return true;
  }

  return false;
}
```

**Recommended Thresholds**:
- **Strict**: `maxDepth = 2` (blocks "Re: Re: Re:")
- **Moderate**: `maxDepth = 3` (blocks after 4th reply)
- **Lenient**: `maxDepth = 5` (blocks after 6th reply)

**Trade-offs**:
- Lower threshold = fewer false positives, but may block legitimate chains
- Higher threshold = more permissive, but allows deeper loops before detection

### Layer 4: Rate Limiting

**Purpose**: Cap total emails sent per time period (damage control)

**Implementation**:
```typescript
class RateLimiter {
  private emailTimestamps: number[] = [];

  canSendEmail(
    hourlyLimit: number = 100,
    dailyLimit: number = 1000
  ): { allowed: boolean; reason?: string } {
    this.cleanOldTimestamps();

    // Check hourly limit
    const hourlyCount = this.getCountInWindow(60 * 60 * 1000);
    if (hourlyCount >= hourlyLimit) {
      return {
        allowed: false,
        reason: `Hourly limit reached (${hourlyCount}/${hourlyLimit})`,
      };
    }

    // Check daily limit
    const dailyCount = this.getCountInWindow(24 * 60 * 60 * 1000);
    if (dailyCount >= dailyLimit) {
      return {
        allowed: false,
        reason: `Daily limit reached (${dailyCount}/${dailyLimit})`,
      };
    }

    return { allowed: true };
  }

  recordEmailSent(): void {
    this.emailTimestamps.push(Date.now());
  }

  private getCountInWindow(windowMs: number): number {
    const cutoff = Date.now() - windowMs;
    return this.emailTimestamps.filter(t => t > cutoff).length;
  }

  private cleanOldTimestamps(): void {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    this.emailTimestamps = this.emailTimestamps.filter(t => t > cutoff);
  }
}
```

**Recommended Limits**:
```typescript
const limits = {
  development: { hourly: 10, daily: 50 },
  staging: { hourly: 50, daily: 200 },
  production: { hourly: 100, daily: 1000 },
};
```

### Layer 5: Circuit Breaker

**Purpose**: Emergency stop for burst sending (rapid email loops)

**Implementation**:
```typescript
class CircuitBreaker {
  private circuitBreakerTripped: boolean = false;
  private circuitBreakerResetTime: number = 0;

  canSendEmail(
    recentEmails: number[],
    threshold: number = 50,
    windowMs: number = 10 * 60 * 1000  // 10 minutes
  ): { allowed: boolean; reason?: string } {
    // Check if already tripped
    if (this.isTripped()) {
      return {
        allowed: false,
        reason: `Circuit breaker tripped until ${new Date(this.circuitBreakerResetTime).toISOString()}`,
      };
    }

    // Count emails in window
    const cutoff = Date.now() - windowMs;
    const burstCount = recentEmails.filter(t => t > cutoff).length;

    // Trip if threshold exceeded
    if (burstCount >= threshold) {
      this.trip();
      return {
        allowed: false,
        reason: 'Circuit breaker tripped due to burst sending',
      };
    }

    return { allowed: true };
  }

  private isTripped(): boolean {
    if (!this.circuitBreakerTripped) return false;

    // Auto-reset after timeout
    if (Date.now() >= this.circuitBreakerResetTime) {
      this.reset();
      return false;
    }

    return true;
  }

  private trip(): void {
    this.circuitBreakerTripped = true;
    this.circuitBreakerResetTime = Date.now() + 60 * 60 * 1000;  // 1 hour

    logger.error('Circuit breaker tripped!', {
      resetTime: new Date(this.circuitBreakerResetTime).toISOString(),
    });
  }

  private reset(): void {
    this.circuitBreakerTripped = false;
    this.circuitBreakerResetTime = 0;
    logger.info('Circuit breaker reset');
  }
}
```

**Recommended Thresholds**:
```typescript
const thresholds = {
  development: { emails: 10, windowMs: 5 * 60 * 1000 },  // 10 emails in 5 min
  staging: { emails: 25, windowMs: 10 * 60 * 1000 },     // 25 emails in 10 min
  production: { emails: 50, windowMs: 10 * 60 * 1000 },  // 50 emails in 10 min
};
```

---

## Testing Strategies

### Unit Tests

**Test 1: Self-Reply Detection**
```typescript
describe('Email Loop Prevention', () => {
  it('should detect self-reply (exact match)', () => {
    const email = {
      from: 'agent@company.com',
      subject: 'Test',
      body: 'Test body',
    };

    const shouldProcess = shouldProcessEmail(email, 'agent@company.com');
    expect(shouldProcess).toBe(false);
  });

  it('should detect self-reply (case-insensitive)', () => {
    const email = {
      from: 'AGENT@COMPANY.COM',
      subject: 'Test',
      body: 'Test body',
    };

    const shouldProcess = shouldProcessEmail(email, 'agent@company.com');
    expect(shouldProcess).toBe(false);
  });

  it('should allow emails from different addresses', () => {
    const email = {
      from: 'user@company.com',
      subject: 'Test',
      body: 'Test body',
    };

    const shouldProcess = shouldProcessEmail(email, 'agent@company.com');
    expect(shouldProcess).toBe(true);
  });
});
```

**Test 2: Bounce Detection**
```typescript
describe('Bounce Detection', () => {
  it('should detect mailer-daemon', () => {
    const email = {
      from: 'mailer-daemon@mailserver.com',
      subject: 'Undeliverable: Your message',
      body: 'Your message could not be delivered',
    };

    expect(isBounceMessage(email)).toBe(true);
  });

  it('should detect bounce via subject line', () => {
    const email = {
      from: 'noreply@service.com',
      subject: 'Delivery Status Notification (Failure)',
      body: 'Your message was not delivered',
    };

    expect(isBounceMessage(email)).toBe(true);
  });
});
```

**Test 3: Subject Chain Detection**
```typescript
describe('Subject Chain Detection', () => {
  it('should detect "Re: Re: Re:" chain (depth 3)', () => {
    const email = {
      from: 'user@company.com',
      subject: 'Re: Re: Re: Original subject',
      body: 'Test',
    };

    expect(isSubjectChain(email, 2)).toBe(true);
  });

  it('should allow single "Re:"', () => {
    const email = {
      from: 'user@company.com',
      subject: 'Re: Original subject',
      body: 'Test',
    };

    expect(isSubjectChain(email, 3)).toBe(false);
  });
});
```

### Integration Tests

**Test 4: Full Email Loop Simulation**
```typescript
describe('Email Loop Simulation', () => {
  it('should prevent infinite loop when agent replies to itself', async () => {
    const emailAgent = new EmailAgent({ address: 'agent@company.com' });

    // Step 1: User sends initial email
    const initialEmail = {
      from: 'user@company.com',
      subject: 'Help with phishing email',
      body: 'I received a suspicious email...',
    };

    await emailAgent.processEmail(initialEmail);
    expect(emailAgent.getSentEmailCount()).toBe(1);

    // Step 2: Simulate agent receiving its own reply
    const agentReply = {
      from: 'agent@company.com',  // ← Agent's own address
      subject: 'Re: Help with phishing email',
      body: 'Your email analysis: ...',
    };

    await emailAgent.processEmail(agentReply);

    // ✅ ASSERT: Agent should NOT reply to itself
    expect(emailAgent.getSentEmailCount()).toBe(1);  // Still 1 (no new reply)
  });

  it('should trip circuit breaker after 50 emails', async () => {
    const emailAgent = new EmailAgent({
      address: 'agent@company.com',
      circuitBreakerThreshold: 50,
    });

    // Simulate 50 rapid emails
    for (let i = 0; i < 50; i++) {
      await emailAgent.processEmail({
        from: `user${i}@company.com`,
        subject: `Email ${i}`,
        body: 'Test',
      });
    }

    expect(emailAgent.getSentEmailCount()).toBe(50);

    // 51st email should be blocked by circuit breaker
    const result = await emailAgent.processEmail({
      from: 'user51@company.com',
      subject: 'Email 51',
      body: 'Test',
    });

    expect(result.sent).toBe(false);
    expect(result.reason).toContain('Circuit breaker');
  });
});
```

### Load Testing

**Test 5: Stress Test Rate Limiter**
```typescript
describe('Rate Limiter Stress Test', () => {
  it('should handle 1000 emails and enforce limits', async () => {
    const rateLimiter = new RateLimiter({
      hourlyLimit: 100,
      dailyLimit: 1000,
    });

    let sentCount = 0;
    let blockedCount = 0;

    // Simulate 1000 email attempts
    for (let i = 0; i < 1000; i++) {
      if (rateLimiter.canSendEmail().allowed) {
        rateLimiter.recordEmailSent();
        sentCount++;
      } else {
        blockedCount++;
      }
    }

    expect(sentCount).toBeLessThanOrEqual(100);  // Hourly limit
    expect(blockedCount).toBeGreaterThan(0);
  });
});
```

---

## Monitoring & Alerting

### Metrics to Track

**Real-Time Metrics**:
```typescript
interface EmailAgentMetrics {
  emailsProcessed: number;         // Total emails processed
  emailsSent: number;              // Total replies sent
  selfRepliesDetected: number;     // Email loop detection hits
  bouncesDetected: number;         // Bounce message detections
  subjectChainsDetected: number;   // Re: Re: Re: detections
  rateLimitHits: number;           // Rate limiter blocks
  circuitBreakerTrips: number;     // Circuit breaker activations
  duplicatesDetected: number;      // Deduplication hits
}
```

**Example Implementation**:
```typescript
class MetricsCollector {
  private metrics: EmailAgentMetrics = {
    emailsProcessed: 0,
    emailsSent: 0,
    selfRepliesDetected: 0,
    bouncesDetected: 0,
    subjectChainsDetected: 0,
    rateLimitHits: 0,
    circuitBreakerTrips: 0,
    duplicatesDetected: 0,
  };

  recordSelfReplyDetection(): void {
    this.metrics.selfRepliesDetected++;
    logger.warn('Self-reply detected', { total: this.metrics.selfRepliesDetected });
  }

  recordCircuitBreakerTrip(): void {
    this.metrics.circuitBreakerTrips++;
    logger.error('Circuit breaker tripped', {
      total: this.metrics.circuitBreakerTrips,
      timestamp: new Date().toISOString(),
    });
  }

  getMetrics(): EmailAgentMetrics {
    return { ...this.metrics };
  }
}
```

### Alert Thresholds

**Critical Alerts** (Immediate Action Required):
```typescript
const criticalAlerts = {
  selfRepliesDetected: { threshold: 1, message: 'Email loop detected! Agent is replying to itself.' },
  circuitBreakerTrips: { threshold: 1, message: 'Circuit breaker tripped! Burst sending detected.' },
  rateLimitHits: { threshold: 90, message: 'Rate limit almost exceeded (90/100).' },
};
```

**Warning Alerts** (Investigation Recommended):
```typescript
const warningAlerts = {
  bouncesDetected: { threshold: 10, message: 'High bounce rate detected.' },
  subjectChainsDetected: { threshold: 5, message: 'Multiple Re: Re: Re: chains detected.' },
  duplicatesDetected: { threshold: 20, message: 'High duplicate email rate.' },
};
```

**Alert Implementation**:
```typescript
function checkAlerts(metrics: EmailAgentMetrics): void {
  // Critical: Self-reply detected
  if (metrics.selfRepliesDetected > 0) {
    sendAlert('CRITICAL', 'Email loop detected!', {
      count: metrics.selfRepliesDetected,
      action: 'Stop agent immediately and investigate',
    });
  }

  // Critical: Circuit breaker tripped
  if (metrics.circuitBreakerTrips > 0) {
    sendAlert('CRITICAL', 'Circuit breaker tripped!', {
      count: metrics.circuitBreakerTrips,
      action: 'Investigate burst sending pattern',
    });
  }

  // Warning: Approaching rate limit
  if (metrics.rateLimitHits > 90) {
    sendAlert('WARNING', 'Rate limit almost exceeded', {
      current: metrics.rateLimitHits,
      limit: 100,
      action: 'Monitor for email loop or unusual activity',
    });
  }
}
```

---

## Recovery Procedures

### Emergency Stop

**If email loop is detected in production**:

**Step 1: Stop the Agent Immediately**
```bash
# Azure Container Apps
az containerapp stop --name phishing-agent --resource-group rg-phishing-agent

# Kubernetes
kubectl scale deployment email-agent --replicas=0

# Docker
docker stop email-agent

# PM2
pm2 stop email-agent
```

**Step 2: Assess Damage**
```bash
# Check sent email count in last hour
grep "Email sent" logs.txt | wc -l

# Check for self-reply pattern
grep "from.*agent@company.com" logs.txt

# Check mailbox for loop emails
# Look for "Re: Re: Re:" chains
```

**Step 3: Clear Mailbox (if needed)**
```bash
# Delete loop emails to prevent re-triggering
# Use email client or Graph API to bulk delete
```

### Root Cause Analysis

**Investigation Checklist**:
- [ ] Review logs for first occurrence of self-reply
- [ ] Identify which layer failed (Loop detection? Rate limiting?)
- [ ] Check if configuration was changed recently
- [ ] Verify all 5 layers of defense are enabled
- [ ] Review recent code deployments
- [ ] Check monitoring alerts (were any missed?)

**Log Analysis**:
```bash
# Find when loop started
grep "Email sent" logs.txt | head -1

# Count self-replies
grep "Self-reply detected" logs.txt | wc -l

# Check if rate limiter was active
grep "Rate limit" logs.txt
```

### Deployment Fix

**Before Redeploying**:
```bash
# Run all email loop tests
npm test -- email-loop

# Verify all safeguards enabled
grep -r "shouldProcessEmail" src/
grep -r "RateLimiter" src/
grep -r "CircuitBreaker" src/

# Check environment variables
echo $RATE_LIMIT_ENABLED  # Should be "true"
echo $MAX_EMAILS_PER_HOUR  # Should be set
```

**Safe Redeploy Procedure**:
```bash
# 1. Deploy with conservative limits
export MAX_EMAILS_PER_HOUR=10  # Very low for testing
export CIRCUIT_BREAKER_THRESHOLD=5

# 2. Deploy to staging first
npm run deploy:staging

# 3. Monitor for 1 hour
tail -f logs/email-agent.log

# 4. If stable, deploy to production with normal limits
export MAX_EMAILS_PER_HOUR=100
npm run deploy:production
```

---

## Checklist: Email Loop Prevention (Complete)

**Before Deploying ANY Email Agent**:

### Code Implementation
- [ ] Layer 1: Self-reply detection implemented
- [ ] Layer 2: Bounce/NDR detection implemented
- [ ] Layer 3: Subject chain detection implemented
- [ ] Layer 4: Rate limiting implemented (hourly, daily)
- [ ] Layer 5: Circuit breaker implemented
- [ ] All layers have unit tests
- [ ] Integration test simulates email loop

### Configuration
- [ ] Agent email address configured
- [ ] Rate limits set (hourly: 100, daily: 1000)
- [ ] Circuit breaker threshold set (50 emails/10 min)
- [ ] Monitoring metrics enabled
- [ ] Alert thresholds configured

### Testing
- [ ] Self-reply test passed
- [ ] Bounce detection test passed
- [ ] Subject chain test passed
- [ ] Rate limiter test passed
- [ ] Circuit breaker test passed
- [ ] Full email loop simulation passed
- [ ] Load test passed (1000 emails)

### Monitoring
- [ ] Real-time metrics dashboard configured
- [ ] Critical alerts configured (self-reply, circuit breaker)
- [ ] Warning alerts configured (bounces, rate limits)
- [ ] Log aggregation enabled
- [ ] Alert notification channels tested

### Documentation
- [ ] Emergency stop procedure documented
- [ ] Recovery procedure documented
- [ ] Monitoring runbook created
- [ ] Team trained on incident response

### Production Readiness
- [ ] Deployed to staging environment
- [ ] 24-hour monitoring period completed
- [ ] No self-replies detected
- [ ] No circuit breaker trips
- [ ] Normal email processing confirmed
- [ ] Team sign-off obtained

---

## Appendix: Code Templates

### Complete Email Processing Function

```typescript
async function processIncomingEmail(
  email: Email,
  config: EmailAgentConfig,
  rateLimiter: RateLimiter,
  circuitBreaker: CircuitBreaker,
  metrics: MetricsCollector
): Promise<{ sent: boolean; reason?: string }> {
  metrics.incrementEmailsProcessed();

  // Layer 1: Self-reply detection
  if (email.from.toLowerCase() === config.agentAddress.toLowerCase()) {
    metrics.recordSelfReplyDetection();
    return { sent: false, reason: 'Self-reply detected' };
  }

  // Layer 2: Bounce detection
  if (isBounceMessage(email)) {
    metrics.recordBounceDetection();
    return { sent: false, reason: 'Bounce message detected' };
  }

  // Layer 3: Subject chain detection
  if (isSubjectChain(email, config.maxReplyDepth)) {
    metrics.recordSubjectChainDetection();
    return { sent: false, reason: 'Subject chain detected' };
  }

  // Layer 4: Rate limiting
  const rateLimitResult = rateLimiter.canSendEmail();
  if (!rateLimitResult.allowed) {
    metrics.recordRateLimitHit();
    return { sent: false, reason: rateLimitResult.reason };
  }

  // Layer 5: Circuit breaker
  const circuitBreakerResult = circuitBreaker.canSendEmail();
  if (!circuitBreakerResult.allowed) {
    metrics.recordCircuitBreakerTrip();
    return { sent: false, reason: circuitBreakerResult.reason };
  }

  // All checks passed - process email
  const analysis = await analyzeEmail(email);
  await sendReply(email.from, analysis);

  rateLimiter.recordEmailSent();
  metrics.incrementEmailsSent();

  return { sent: true };
}
```

---

**Document Version**: 1.0
**Author**: Engineering Team
**Last Updated**: October 22, 2025
**Next Review**: After next email agent deployment

**Related Documents**:
- [Azure Email Loop Incident Report](./AZURE_EMAIL_LOOP_INCIDENT.md)
- [Lessons Learned](./LESSONS_LEARNED.md)
- [Architecture Documentation](./ARCHITECTURE.md)
