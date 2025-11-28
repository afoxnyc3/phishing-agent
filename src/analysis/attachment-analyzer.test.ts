import { describe, it, expect, jest } from '@jest/globals';

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { AttachmentAnalyzer } = await import('./attachment-analyzer.js');

describe('AttachmentAnalyzer', () => {
  describe('Empty/No Attachments', () => {
    it('should return empty result for undefined attachments', () => {
      const result = AttachmentAnalyzer.analyze(undefined);

      expect(result.hasRiskyAttachments).toBe(false);
      expect(result.indicators).toHaveLength(0);
      expect(result.riskLevel).toBe('none');
      expect(result.totalAttachments).toBe(0);
    });

    it('should return empty result for empty array', () => {
      const result = AttachmentAnalyzer.analyze([]);

      expect(result.hasRiskyAttachments).toBe(false);
      expect(result.indicators).toHaveLength(0);
      expect(result.riskLevel).toBe('none');
    });
  });

  describe('Dangerous Executable Extensions', () => {
    it('should detect .exe files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'malware.exe', contentType: 'application/x-msdownload', size: 5000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(true);
      expect(result.riskLevel).toBe('critical');
      expect(result.indicators).toContainEqual(
        expect.objectContaining({
          type: 'attachment',
          severity: 'critical',
          description: expect.stringContaining('.exe'),
        })
      );
    });

    it('should detect .scr files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'screensaver.scr', contentType: 'application/octet-stream', size: 10000 },
      ]);

      expect(result.riskLevel).toBe('critical');
      expect(result.indicators[0].description).toContain('.scr');
    });

    it('should detect .bat files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'script.bat', contentType: 'text/plain', size: 500 },
      ]);

      expect(result.riskLevel).toBe('critical');
      expect(result.indicators[0].description).toContain('.bat');
    });

    it('should detect .vbs files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'virus.vbs', contentType: 'text/vbscript', size: 1000 },
      ]);

      expect(result.riskLevel).toBe('critical');
      expect(result.indicators[0].description).toContain('.vbs');
    });

    it('should detect .cmd files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'command.cmd', contentType: 'text/plain', size: 500 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });

    it('should detect .js files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'script.js', contentType: 'application/javascript', size: 2000 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });

    it('should detect .hta files as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'app.hta', contentType: 'application/hta', size: 3000 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });
  });

  describe('Macro-Enabled Documents', () => {
    it('should detect .docm files as high risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'document.docm', contentType: 'application/vnd.ms-word', size: 50000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(true);
      expect(result.riskLevel).toBe('high');
      expect(result.indicators).toContainEqual(
        expect.objectContaining({
          type: 'attachment',
          severity: 'high',
          description: expect.stringContaining('.docm'),
        })
      );
    });

    it('should detect .xlsm files as high risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'spreadsheet.xlsm', contentType: 'application/vnd.ms-excel', size: 100000 },
      ]);

      expect(result.riskLevel).toBe('high');
      expect(result.indicators[0].description).toContain('.xlsm');
    });

    it('should detect .pptm files as high risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'presentation.pptm', contentType: 'application/vnd.ms-powerpoint', size: 200000 },
      ]);

      expect(result.riskLevel).toBe('high');
    });

    it('should detect .dotm files as high risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'template.dotm', contentType: 'application/vnd.ms-word', size: 30000 },
      ]);

      expect(result.riskLevel).toBe('high');
    });
  });

  describe('Double Extension Detection', () => {
    it('should detect invoice.pdf.exe as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'invoice.pdf.exe', contentType: 'application/pdf', size: 5000 },
      ]);

      expect(result.riskLevel).toBe('critical');
      expect(result.indicators).toContainEqual(
        expect.objectContaining({
          type: 'attachment',
          severity: 'critical',
          description: expect.stringContaining('Double extension'),
        })
      );
    });

    it('should detect document.doc.scr as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'document.doc.scr', contentType: 'application/msword', size: 10000 },
      ]);

      expect(result.riskLevel).toBe('critical');
      expect(result.indicators.some(i => i.description.includes('Double extension'))).toBe(true);
    });

    it('should detect image.jpg.vbs as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'image.jpg.vbs', contentType: 'image/jpeg', size: 2000 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });

    it('should detect report.xlsx.bat as critical', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'report.xlsx.bat', contentType: 'application/vnd.ms-excel', size: 1500 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });

    it('should handle uppercase double extensions', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'Document.PDF.EXE', contentType: 'application/pdf', size: 5000 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });
  });

  describe('Archive Files', () => {
    it('should detect .zip files as medium risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'files.zip', contentType: 'application/zip', size: 500000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(true);
      expect(result.riskLevel).toBe('medium');
      expect(result.indicators[0].description).toContain('.zip');
    });

    it('should detect .rar files as medium risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'archive.rar', contentType: 'application/x-rar', size: 1000000 },
      ]);

      expect(result.riskLevel).toBe('medium');
    });

    it('should detect .7z files as medium risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'compressed.7z', contentType: 'application/x-7z-compressed', size: 800000 },
      ]);

      expect(result.riskLevel).toBe('medium');
    });

    it('should detect .iso files as medium risk', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'software.iso', contentType: 'application/x-iso9660-image', size: 5000000 },
      ]);

      expect(result.riskLevel).toBe('medium');
    });
  });

  describe('File Size Anomalies', () => {
    it('should flag suspiciously small files', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'tiny.txt', contentType: 'text/plain', size: 50 },
      ]);

      expect(result.hasRiskyAttachments).toBe(true);
      expect(result.indicators).toContainEqual(
        expect.objectContaining({
          type: 'attachment',
          severity: 'medium',
          description: expect.stringContaining('small'),
        })
      );
    });

    it('should flag unusually large files', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'huge.pdf', contentType: 'application/pdf', size: 30 * 1024 * 1024 },
      ]);

      expect(result.hasRiskyAttachments).toBe(true);
      expect(result.indicators).toContainEqual(
        expect.objectContaining({
          type: 'attachment',
          severity: 'low',
          description: expect.stringContaining('large'),
        })
      );
    });

    it('should not flag normal sized files', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'normal.pdf', contentType: 'application/pdf', size: 500000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
      expect(result.riskLevel).toBe('none');
    });
  });

  describe('Safe Attachments', () => {
    it('should not flag safe document types', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'document.pdf', contentType: 'application/pdf', size: 100000 },
        { filename: 'report.docx', contentType: 'application/vnd.ms-word', size: 50000 },
        { filename: 'data.xlsx', contentType: 'application/vnd.ms-excel', size: 200000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
      expect(result.riskLevel).toBe('none');
      expect(result.totalAttachments).toBe(3);
      expect(result.riskyAttachments).toBe(0);
    });

    it('should not flag image attachments', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'photo.jpg', contentType: 'image/jpeg', size: 500000 },
        { filename: 'logo.png', contentType: 'image/png', size: 50000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
      expect(result.riskLevel).toBe('none');
    });

    it('should not flag text files', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'notes.txt', contentType: 'text/plain', size: 5000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
    });
  });

  describe('Multiple Attachments', () => {
    it('should analyze all attachments and count risky ones', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'safe.pdf', contentType: 'application/pdf', size: 100000 },
        { filename: 'malware.exe', contentType: 'application/x-msdownload', size: 5000 },
        { filename: 'macro.xlsm', contentType: 'application/vnd.ms-excel', size: 50000 },
      ]);

      expect(result.totalAttachments).toBe(3);
      expect(result.riskyAttachments).toBe(2);
      expect(result.riskLevel).toBe('critical');
    });

    it('should detect highest risk level from multiple attachments', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'archive.zip', contentType: 'application/zip', size: 100000 },
        { filename: 'document.docm', contentType: 'application/vnd.ms-word', size: 50000 },
      ]);

      expect(result.riskLevel).toBe('high');
    });
  });

  describe('Case Insensitivity', () => {
    it('should detect uppercase extensions', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'MALWARE.EXE', contentType: 'application/x-msdownload', size: 5000 },
      ]);

      expect(result.riskLevel).toBe('critical');
    });

    it('should detect mixed case extensions', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'Document.DocM', contentType: 'application/vnd.ms-word', size: 50000 },
      ]);

      expect(result.riskLevel).toBe('high');
    });
  });

  describe('Edge Cases', () => {
    it('should handle files without extensions', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'noextension', contentType: 'application/octet-stream', size: 5000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
    });

    it('should handle files with only a dot', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'file.', contentType: 'application/octet-stream', size: 5000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
    });

    it('should handle empty filename', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: '', contentType: 'application/octet-stream', size: 5000 },
      ]);

      expect(result.hasRiskyAttachments).toBe(false);
    });

    it('should handle zero-byte files', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'empty.txt', contentType: 'text/plain', size: 0 },
      ]);

      expect(result.indicators.some(i => i.description.includes('small'))).toBe(true);
    });
  });

  describe('Confidence Scores', () => {
    it('should have high confidence for dangerous extensions', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'virus.exe', contentType: 'application/x-msdownload', size: 5000 },
      ]);

      const indicator = result.indicators.find(i => i.description.includes('.exe'));
      expect(indicator?.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it('should have very high confidence for double extensions', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'invoice.pdf.exe', contentType: 'application/pdf', size: 5000 },
      ]);

      const indicator = result.indicators.find(i => i.description.includes('Double'));
      expect(indicator?.confidence).toBeGreaterThanOrEqual(0.95);
    });

    it('should have moderate confidence for archives', () => {
      const result = AttachmentAnalyzer.analyze([
        { filename: 'files.zip', contentType: 'application/zip', size: 100000 },
      ]);

      const indicator = result.indicators.find(i => i.description.includes('.zip'));
      expect(indicator?.confidence).toBeLessThan(0.8);
    });
  });
});
