import { describe, it, expect } from 'vitest';
import { EmailParser } from './email-parser.js';

describe('EmailParser', () => {
  describe('Basic Email Parsing', () => {
    it('should parse simple email with standard headers', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <abc123@example.com>

This is the email body.`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.from).toBe('sender@example.com');
      expect(parsed.headers.to).toBe('recipient@test.com');
      expect(parsed.headers.subject).toBe('Test Email');
      expect(parsed.headers.date).toBe('Mon, 1 Jan 2024 12:00:00 GMT');
      expect(parsed.headers['message-id']).toBe('<abc123@example.com>');
      expect(parsed.body).toBe('This is the email body.');
    });

    it('should parse email with name and angle brackets', () => {
      const rawEmail = `From: John Doe <john@example.com>
To: Jane Smith <jane@test.com>
Subject: Hello
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>

Hello!`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.from).toBe('John Doe <john@example.com>');
      expect(parsed.headers.to).toBe('Jane Smith <jane@test.com>');
    });

    it('should handle multi-line headers', () => {
      const rawEmail = `From: sender@example.com
Subject: This is a very long subject line
 that continues on the next line
 and even another line
Date: Mon, 1 Jan 2024 12:00:00 GMT
To: recipient@test.com
Message-ID: <test@example.com>

Body content.`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.subject).toContain('very long subject');
      expect(parsed.headers.subject).toContain('continues on the next line');
      expect(parsed.headers.subject).toContain('even another line');
    });
  });

  describe('Authentication Headers', () => {
    it('should extract SPF header', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
Received-SPF: pass

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['received-spf']).toBe('pass');
    });

    it('should extract authentication results header', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['authentication-results']).toBe('spf=pass; dkim=pass; dmarc=pass');
    });

    it('should extract DMARC results header', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
DMARC-Results: pass

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['dmarc-results']).toBe('pass');
    });

    it('should extract X-Originating-IP header', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
X-Originating-IP: 192.168.1.100

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['x-originating-ip']).toBe('192.168.1.100');
    });

    it('should extract Reply-To header', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
Reply-To: different@example.org

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['reply-to']).toBe('different@example.org');
    });

    it('should extract Received header', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
Received: from mail.example.com

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.received).toBe('from mail.example.com');
    });
  });

  describe('Email Address Extraction', () => {
    it('should extract email from angle bracket format', () => {
      const email = EmailParser.extractEmailAddress('John Doe <john@example.com>');
      expect(email).toBe('john@example.com');
    });

    it('should extract email without angle brackets', () => {
      const email = EmailParser.extractEmailAddress('john@example.com');
      expect(email).toBe('john@example.com');
    });

    it('should handle email with extra whitespace', () => {
      const email = EmailParser.extractEmailAddress('  john@example.com  ');
      expect(email).toBe('john@example.com');
    });

    it('should extract complex formatted email', () => {
      const email = EmailParser.extractEmailAddress('"John Doe" <john.doe@example.com>');
      expect(email).toBe('john.doe@example.com');
    });
  });

  describe('Domain Extraction', () => {
    it('should extract domain from email address', () => {
      const domain = EmailParser.extractDomain('john@example.com');
      expect(domain).toBe('example.com');
    });

    it('should extract domain from angle bracket format', () => {
      const domain = EmailParser.extractDomain('John Doe <john@example.com>');
      expect(domain).toBe('example.com');
    });

    it('should extract subdomain correctly', () => {
      const domain = EmailParser.extractDomain('user@mail.google.com');
      expect(domain).toBe('mail.google.com');
    });

    it('should return empty string for invalid email', () => {
      const domain = EmailParser.extractDomain('invalid-email');
      expect(domain).toBe('');
    });
  });

  describe('Display Name Extraction', () => {
    it('should extract display name from angle bracket format', () => {
      const name = EmailParser.extractDisplayName('John Doe <john@example.com>');
      expect(name).toBe('John Doe');
    });

    it('should extract display name with quotes', () => {
      const name = EmailParser.extractDisplayName('"John Doe" <john@example.com>');
      expect(name).toBe('John Doe');
    });

    it('should return empty string when no display name', () => {
      const name = EmailParser.extractDisplayName('john@example.com');
      expect(name).toBe('');
    });

    it('should handle display name with special characters', () => {
      const name = EmailParser.extractDisplayName('John "Johnny" Doe <john@example.com>');
      expect(name).toContain('John');
      expect(name).toContain('Johnny');
    });
  });

  describe('Body Parsing', () => {
    it('should parse multi-line body', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>

Line 1 of body
Line 2 of body
Line 3 of body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.body).toContain('Line 1 of body');
      expect(parsed.body).toContain('Line 2 of body');
      expect(parsed.body).toContain('Line 3 of body');
    });

    it('should parse HTML body', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>

<html>
<body>
<p>HTML content</p>
</body>
</html>`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.body).toContain('<html>');
      expect(parsed.body).toContain('<p>HTML content</p>');
    });

    it('should handle empty body', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>

`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.body).toBeUndefined();
    });

    it('should trim whitespace from body', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>


Body content
   `;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.body).toBe('Body content');
    });
  });

  describe('Edge Cases', () => {
    it('should generate message ID if missing', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['message-id']).toMatch(/generated-\d+@parser/);
    });

    it('should use current date if date header missing', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Message-ID: <test@example.com>

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.date).toBeTruthy();
      expect(parsed.headers.date).toMatch(/\d{4}/); // Should contain year
    });

    it('should handle missing required headers gracefully', () => {
      const rawEmail = `Subject: Only Subject

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.subject).toBe('Only Subject');
      expect(parsed.headers.from).toBe('');
      expect(parsed.headers.to).toBe('');
      expect(parsed.headers['message-id']).toMatch(/generated-/);
    });

    it('should handle CRLF line endings', () => {
      const rawEmail =
        'From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\nDate: Mon, 1 Jan 2024 12:00:00 GMT\r\nMessage-ID: <test@example.com>\r\n\r\nBody';

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.from).toBe('sender@example.com');
      expect(parsed.headers.to).toBe('recipient@test.com');
      expect(parsed.body).toBe('Body');
    });

    it('should handle case-insensitive header names', () => {
      const rawEmail = `FROM: sender@example.com
TO: recipient@test.com
SUBJECT: Test
DATE: Mon, 1 Jan 2024 12:00:00 GMT
MESSAGE-ID: <test@example.com>

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers.from).toBe('sender@example.com');
      expect(parsed.headers.to).toBe('recipient@test.com');
      expect(parsed.headers.subject).toBe('Test');
    });

    it('should store raw headers in map', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.rawHeaders.size).toBeGreaterThan(0);
      expect(parsed.rawHeaders.get('from')).toContain('sender@example.com');
      expect(parsed.rawHeaders.get('subject')).toContain('Test');
    });

    it('should handle custom headers', () => {
      const rawEmail = `From: sender@example.com
To: recipient@test.com
Subject: Test
Date: Mon, 1 Jan 2024 12:00:00 GMT
Message-ID: <test@example.com>
X-Custom-Header: custom-value

Body`;

      const parsed = EmailParser.parseEmail(rawEmail);

      expect(parsed.headers['x-custom-header']).toBe('custom-value');
    });
  });
});
