import { describe, it, expect, jest, beforeEach } from '@jest/globals';

// Mock modules using unstable_mockModule for ESM compatibility
jest.unstable_mockModule('axios', () => ({
  default: {
    create: jest.fn(() => ({
      get: jest.fn(),
      post: jest.fn(),
    })),
  },
}));

jest.unstable_mockModule('node-cache', () => ({
  default: jest.fn().mockImplementation(() => ({
    get: jest.fn().mockReturnValue(null),
    set: jest.fn(),
  })),
}));

jest.unstable_mockModule('../lib/config.js', () => ({
  config: {
    threatIntel: {
      enabled: true,
      virusTotalApiKey: 'test-vt-key',
      abuseIpDbApiKey: 'test-abuseipdb-key',
      urlScanApiKey: 'test-urlscan-key',
      timeoutMs: 5000,
      cacheTtlMs: 300000,
    },
  },
}));

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Import after mocks are set up
const { ThreatIntelService } = await import('./threat-intel.js');

describe('ThreatIntelService', () => {
  let service: InstanceType<typeof ThreatIntelService>;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new ThreatIntelService();
  });

  describe('Service Initialization', () => {
    it('should initialize service', () => {
      expect(service).toBeDefined();
    });

    it('should initialize with cache', () => {
      expect(service).toHaveProperty('cache');
    });
  });

  describe('Disabled Service', () => {
    it('should return empty result when disabled', async () => {
      // Override enabled flag
      (service as any).enabled = false;

      const result = await service.enrichEmail('test@example.com', '1.2.3.4', []);

      expect(result.indicators.length).toBe(0);
      expect(result.riskContribution).toBe(0);
    });
  });

  describe('Domain Extraction', () => {
    it('should extract domain from email', () => {
      const domain = (service as any).extractDomain('user@example.com');
      expect(domain).toBe('example.com');
    });

    it('should extract domain from email with subdomain', () => {
      const domain = (service as any).extractDomain('user@mail.google.com');
      expect(domain).toBe('mail.google.com');
    });

    it('should return null for invalid email', () => {
      const domain = (service as any).extractDomain('invalid-email');
      expect(domain).toBeNull();
    });
  });

  describe('URL Reputation Checking', () => {
    it('should return null when VirusTotal client not configured', async () => {
      (service as any).virusTotalClient = null;

      const result = await service.checkUrlReputation('https://example.com');

      expect(result).toBeNull();
    });

    it('should return cached result if available', async () => {
      const cachedResult = {
        url: 'https://example.com',
        malicious: true,
        maliciousCount: 5,
        totalScans: 10,
        detectedBy: ['Scanner1'],
        confidenceScore: 0.5,
      };

      // Mock the cache and ensure client is set
      const getCacheMock = jest.fn().mockReturnValue(cachedResult);
      (service as any).cache = { get: getCacheMock, set: jest.fn() };
      (service as any).virusTotalClient = { get: jest.fn() }; // Mock client to bypass null check

      const result = await service.checkUrlReputation('https://example.com');

      expect(result).toEqual(cachedResult);
      expect(getCacheMock).toHaveBeenCalled();
    });
  });

  describe('IP Reputation Checking', () => {
    it('should return null when AbuseIPDB client not configured', async () => {
      (service as any).abuseIpDbClient = null;

      const result = await service.checkIpReputation('1.2.3.4');

      expect(result).toBeNull();
    });

    it('should return cached result if available', async () => {
      const cachedResult = {
        ip: '1.2.3.4',
        malicious: true,
        abuseConfidenceScore: 75,
        totalReports: 10,
      };

      // Mock the cache and ensure client is set
      const getCacheMock = jest.fn().mockReturnValue(cachedResult);
      (service as any).cache = { get: getCacheMock, set: jest.fn() };
      (service as any).abuseIpDbClient = { get: jest.fn() }; // Mock client to bypass null check

      const result = await service.checkIpReputation('1.2.3.4');

      expect(result).toEqual(cachedResult);
      expect(getCacheMock).toHaveBeenCalled();
    });
  });

  describe('Domain Age Checking', () => {
    it('should return stub result for domain age', async () => {
      const result = await service.checkDomainAge('example.com');

      expect(result).not.toBeNull();
      expect(result?.domain).toBe('example.com');
      expect(result?.ageDays).toBeDefined();
      expect(result?.createdDate).toBeDefined();
    });

    it('should cache domain age results', async () => {
      const setCacheMock = jest.fn();
      (service as any).cache.set = setCacheMock;

      await service.checkDomainAge('example.com');

      expect(setCacheMock).toHaveBeenCalled();
    });

    it('should return cached domain age if available', async () => {
      const cachedResult = {
        domain: 'example.com',
        ageDays: 10,
        createdDate: '2024-01-01',
        suspicious: true,
        suspicionReasons: ['Too new'],
      };

      (service as any).cache.get = jest.fn().mockReturnValue(cachedResult);

      const result = await service.checkDomainAge('example.com');

      expect(result).toEqual(cachedResult);
    });
  });

  describe('Parallel Lookups', () => {
    it('should perform parallel lookups for URLs, IP, and domain', async () => {
      const checkUrlReputationSpy = jest
        .spyOn(service, 'checkUrlReputation')
        .mockResolvedValue(null);
      const checkIpReputationSpy = jest
        .spyOn(service, 'checkIpReputation')
        .mockResolvedValue(null);
      const checkDomainAgeSpy = jest
        .spyOn(service, 'checkDomainAge')
        .mockResolvedValue(null);

      await service.enrichEmail('test@example.com', '1.2.3.4', ['https://test.com', 'https://test2.com']);

      expect(checkUrlReputationSpy).toHaveBeenCalled();
      expect(checkIpReputationSpy).toHaveBeenCalledWith('1.2.3.4');
      expect(checkDomainAgeSpy).toHaveBeenCalledWith('example.com');
    });

    it('should limit URL checks to first 3 URLs', async () => {
      const checkUrlReputationSpy = jest
        .spyOn(service, 'checkUrlReputation')
        .mockResolvedValue(null);

      const urls = Array(10).fill('https://test.com');
      await service.enrichEmail('test@example.com', null, urls);

      expect(checkUrlReputationSpy).toHaveBeenCalledTimes(3);
    });

    it('should skip IP lookup if no IP provided', async () => {
      const checkIpReputationSpy = jest
        .spyOn(service, 'checkIpReputation')
        .mockResolvedValue(null);

      await service.enrichEmail('test@example.com', null, []);

      expect(checkIpReputationSpy).not.toHaveBeenCalled();
    });
  });

  describe('Result Processing', () => {
    it('should process malicious URL result', async () => {
      jest.spyOn(service, 'checkUrlReputation').mockResolvedValue({
        url: 'https://evil.com',
        malicious: true,
        maliciousCount: 10,
        totalScans: 15,
        detectedBy: ['Scanner1', 'Scanner2', 'Scanner3'],
        confidenceScore: 0.8,
      });

      const result = await service.enrichEmail('test@example.com', null, ['https://evil.com']);

      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.indicators[0].type).toBe('url');
      expect(result.indicators[0].severity).toBe('critical');
      expect(result.riskContribution).toBeGreaterThan(0);
    });

    it('should process malicious IP result', async () => {
      jest.spyOn(service, 'checkIpReputation').mockResolvedValue({
        ip: '1.2.3.4',
        malicious: true,
        abuseConfidenceScore: 85,
        totalReports: 50,
      });

      const result = await service.enrichEmail('test@example.com', '1.2.3.4', []);

      const ipIndicator = result.indicators.find(i => i.type === 'sender' && i.description.includes('IP'));
      expect(ipIndicator).toBeDefined();
      expect(ipIndicator?.severity).toBe('high');
      expect(result.riskContribution).toBeGreaterThan(0);
    });

    it('should process new domain result', async () => {
      jest.spyOn(service, 'checkDomainAge').mockResolvedValue({
        domain: 'newdomain.com',
        ageDays: 5,
        createdDate: '2024-01-01',
        suspicious: true,
        suspicionReasons: ['Very new domain'],
      });

      const result = await service.enrichEmail('test@newdomain.com', null, []);

      const domainIndicator = result.indicators.find(i => i.description.includes('Domain registered'));
      expect(domainIndicator).toBeDefined();
      expect(domainIndicator?.severity).toBe('high');
      expect(result.riskContribution).toBeGreaterThan(0);
    });

    it('should not flag old domains', async () => {
      jest.spyOn(service, 'checkDomainAge').mockResolvedValue({
        domain: 'olddomain.com',
        ageDays: 365,
        createdDate: '2023-01-01',
        suspicious: false,
        suspicionReasons: [],
      });

      const result = await service.enrichEmail('test@olddomain.com', null, []);

      const domainIndicator = result.indicators.find(i => i.description.includes('Domain registered'));
      expect(domainIndicator).toBeUndefined();
    });
  });

  describe('Risk Contribution', () => {
    it('should increase risk for malicious URL with high confidence', async () => {
      jest.spyOn(service, 'checkUrlReputation').mockResolvedValue({
        url: 'https://evil.com',
        malicious: true,
        maliciousCount: 15,
        totalScans: 20,
        detectedBy: ['Scanner1'],
        confidenceScore: 0.9,
      });

      const result = await service.enrichEmail('test@example.com', null, ['https://evil.com']);

      expect(result.riskContribution).toBeGreaterThan(2.0);
    });

    it('should increase risk for high abuse confidence IP', async () => {
      jest.spyOn(service, 'checkIpReputation').mockResolvedValue({
        ip: '1.2.3.4',
        malicious: true,
        abuseConfidenceScore: 95,
        totalReports: 100,
      });

      const result = await service.enrichEmail('test@example.com', '1.2.3.4', []);

      expect(result.riskContribution).toBeGreaterThan(1.5);
    });

    it('should increase risk more for very new domains', async () => {
      jest.spyOn(service, 'checkDomainAge').mockResolvedValue({
        domain: 'newdomain.com',
        ageDays: 3,
        createdDate: '2024-01-01',
        suspicious: true,
        suspicionReasons: [],
      });

      const result = await service.enrichEmail('test@newdomain.com', null, []);

      expect(result.riskContribution).toBeGreaterThanOrEqual(2.0);
    });
  });

  describe('Error Handling', () => {
    it('should handle API errors gracefully', async () => {
      jest.spyOn(service, 'checkUrlReputation').mockRejectedValue(new Error('API Error'));

      const result = await service.enrichEmail('test@example.com', null, ['https://test.com']);

      // Should not throw, should return partial results
      expect(result).toBeDefined();
      expect(result.indicators).toBeDefined();
    });

    it('should continue processing other lookups if one fails', async () => {
      jest.spyOn(service, 'checkUrlReputation').mockRejectedValue(new Error('URL API Error'));
      jest.spyOn(service, 'checkIpReputation').mockResolvedValue({
        ip: '1.2.3.4',
        malicious: true,
        abuseConfidenceScore: 75,
        totalReports: 10,
      });

      const result = await service.enrichEmail('test@example.com', '1.2.3.4', ['https://test.com']);

      // IP result should still be processed
      expect(result.indicators.some(i => i.type === 'sender')).toBe(true);
    });
  });

  describe('Health Check', () => {
    it('should return true when enabled and clients configured', async () => {
      (service as any).enabled = true;
      (service as any).virusTotalClient = {};

      const health = await service.healthCheck();

      expect(health).toBe(true);
    });

    it('should return false when disabled', async () => {
      (service as any).enabled = false;
      (service as any).virusTotalClient = {};

      const health = await service.healthCheck();

      expect(health).toBe(false);
    });

    it('should return false when no clients configured', async () => {
      (service as any).enabled = true;
      (service as any).virusTotalClient = null;
      (service as any).abuseIpDbClient = null;

      const health = await service.healthCheck();

      expect(health).toBe(false);
    });
  });

  describe('Cache Functionality', () => {
    it('should use cache for URL reputation', async () => {
      const cachedResult = {
        url: 'https://cached.com',
        malicious: false,
        maliciousCount: 0,
        totalScans: 10,
        detectedBy: [],
        confidenceScore: 0,
      };
      const getCacheMock = jest.fn().mockReturnValue(cachedResult);
      (service as any).cache = { get: getCacheMock, set: jest.fn() };
      (service as any).virusTotalClient = { get: jest.fn() }; // Mock client to bypass null check

      const result = await service.checkUrlReputation('https://cached.com');

      expect(result).toEqual(cachedResult);
      expect(getCacheMock).toHaveBeenCalledWith('vt-url-https://cached.com');
    });

    it('should use cache for IP reputation', async () => {
      const cachedResult = {
        ip: '1.2.3.4',
        malicious: false,
        abuseConfidenceScore: 0,
        totalReports: 0,
      };
      const getCacheMock = jest.fn().mockReturnValue(cachedResult);
      (service as any).cache = { get: getCacheMock, set: jest.fn() };
      (service as any).abuseIpDbClient = { get: jest.fn() }; // Mock client to bypass null check

      const result = await service.checkIpReputation('1.2.3.4');

      expect(result).toEqual(cachedResult);
      expect(getCacheMock).toHaveBeenCalledWith('abuseipdb-1.2.3.4');
    });

    it('should use cache for domain age', async () => {
      const getCacheMock = jest.fn().mockReturnValue({
        domain: 'example.com',
        ageDays: 100,
        createdDate: '2023-01-01',
        suspicious: false,
        suspicionReasons: [],
      });
      (service as any).cache.get = getCacheMock;

      await service.checkDomainAge('example.com');

      expect(getCacheMock).toHaveBeenCalledWith('domain-age-example.com');
    });
  });
});
