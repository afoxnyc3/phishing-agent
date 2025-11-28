import { evaluateEmailGuards, __testResetMessageIdCache } from './email-processor.js';

describe('email guardrails', () => {
  const mailboxAddress = 'phishing@company.com';

  beforeEach(() => {
    __testResetMessageIdCache();
    delete process.env.ALLOWED_SENDER_EMAILS;
    delete process.env.ALLOWED_SENDER_DOMAINS;
  });

  afterEach(() => {
    delete process.env.ALLOWED_SENDER_EMAILS;
    delete process.env.ALLOWED_SENDER_DOMAINS;
  });

  it('blocks self-sent messages', () => {
    const result = evaluateEmailGuards(
      {
        id: 'test-1',
        from: { emailAddress: { address: mailboxAddress } },
        internetMessageId: 'id-1',
      },
      mailboxAddress
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('self-sender-detected');
  });

  it('blocks auto responders via headers', () => {
    const result = evaluateEmailGuards(
      {
        id: 'test-2',
        from: { emailAddress: { address: 'noreply@service.com' } },
        internetMessageId: 'id-2',
        internetMessageHeaders: [{ name: 'Auto-Submitted', value: 'auto-replied' }],
      },
      mailboxAddress
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('auto-responder-detected');
  });

  it('blocks duplicate message IDs', () => {
    const email = {
      id: 'test-3',
      from: { emailAddress: { address: 'user@example.com' } },
      internetMessageId: 'id-3',
    };

    const first = evaluateEmailGuards(email, mailboxAddress);
    const second = evaluateEmailGuards(email, mailboxAddress);

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
    expect(second.reason).toBe('duplicate-message-id');
  });

  it('enforces allowlists when configured', () => {
    process.env.ALLOWED_SENDER_DOMAINS = 'trusted.com';

    const allowed = evaluateEmailGuards(
      {
        id: 'test-4',
        from: { emailAddress: { address: 'user@trusted.com' } },
        internetMessageId: 'id-4',
      },
      mailboxAddress
    );

    const blocked = evaluateEmailGuards(
      {
        id: 'test-5',
        from: { emailAddress: { address: 'user@other.com' } },
        internetMessageId: 'id-5',
      },
      mailboxAddress
    );

    expect(allowed.allowed).toBe(true);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toBe('sender-not-allowlisted');
  });
});
