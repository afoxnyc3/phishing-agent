import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';

// Create mock logger before importing modules
const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

// Mock winston using unstable_mockModule for ESM
jest.unstable_mockModule('winston', () => ({
  default: {
    createLogger: jest.fn(() => mockLogger),
    format: {
      combine: jest.fn((...args: unknown[]) => args),
      timestamp: jest.fn(),
      errors: jest.fn(),
      json: jest.fn(),
      colorize: jest.fn(),
      simple: jest.fn(),
    },
    transports: {
      Console: jest.fn(),
    },
  },
}));

// Import after mocking
const { SecurityLogger, PerformanceTimer, securityLogger } = await import('./logger.js');

describe('Logger Module', () => {
  let testLogger: InstanceType<typeof SecurityLogger>;
  let mockWinstonLogger: typeof mockLogger;

  beforeEach(() => {
    jest.clearAllMocks();
    mockWinstonLogger = mockLogger;
    testLogger = new SecurityLogger();
  });

  describe('SecurityLogger', () => {
    describe('Log Level Methods', () => {
      it('should log info messages', () => {
        testLogger.info('Test info message');

        expect(mockWinstonLogger.info).toHaveBeenCalled();
        expect(mockWinstonLogger.info).toHaveBeenCalledWith('Test info message', undefined);
      });

      it('should log info messages with metadata', () => {
        const meta = { userId: '123', action: 'login' };
        testLogger.info('User logged in', meta);

        expect(mockWinstonLogger.info).toHaveBeenCalledWith('User logged in', meta);
      });

      it('should log warn messages', () => {
        testLogger.warn('Test warning');

        expect(mockWinstonLogger.warn).toHaveBeenCalledWith('Test warning', undefined);
      });

      it('should log warn messages with metadata', () => {
        const meta = { threshold: 100, actual: 150 };
        testLogger.warn('Threshold exceeded', meta);

        expect(mockWinstonLogger.warn).toHaveBeenCalledWith('Threshold exceeded', meta);
      });

      it('should log error messages', () => {
        const error = new Error('Test error');
        testLogger.error('An error occurred', error);

        expect(mockWinstonLogger.error).toHaveBeenCalledWith('An error occurred', {
          error: 'Test error',
          stack: expect.any(String),
        });
      });

      it('should log error messages without error object', () => {
        testLogger.error('Generic error');

        expect(mockWinstonLogger.error).toHaveBeenCalledWith('Generic error', undefined);
      });

      it('should log error with string instead of Error object', () => {
        testLogger.error('Error occurred', 'String error');

        expect(mockWinstonLogger.error).toHaveBeenCalledWith('Error occurred', {
          error: 'String error',
        });
      });

      it('should preserve structured metadata objects in error()', () => {
        const meta = { analysisId: 'abc', messageId: 'msg-1', error: 'something failed' };
        testLogger.error('Analysis failed', meta);

        expect(mockWinstonLogger.error).toHaveBeenCalledWith('Analysis failed', meta);
      });

      it('should log debug messages', () => {
        testLogger.debug('Debug message');

        expect(mockWinstonLogger.debug).toHaveBeenCalledWith('Debug message', undefined);
      });

      it('should log debug messages with metadata', () => {
        const meta = { step: 'validation', data: { count: 5 } };
        testLogger.debug('Processing step', meta);

        expect(mockWinstonLogger.debug).toHaveBeenCalledWith('Processing step', meta);
      });

      it('should log security events with special prefix', () => {
        testLogger.security('Phishing email detected');

        expect(mockWinstonLogger.info).toHaveBeenCalledWith('[SECURITY] Phishing email detected', undefined);
      });

      it('should log security events with metadata', () => {
        const meta = { riskScore: 8.5, messageId: 'abc123' };
        testLogger.security('High risk email', meta);

        expect(mockWinstonLogger.info).toHaveBeenCalledWith('[SECURITY] High risk email', meta);
      });
    });

    describe('Performance Metrics', () => {
      it('should add performance metric', () => {
        const metric = {
          timestamp: new Date(),
          operation: 'test-op',
          duration: 100,
          success: true,
        };

        testLogger.addPerformanceMetric(metric);

        const metrics = testLogger.getPerformanceMetrics();
        expect(metrics).toHaveLength(1);
        expect(metrics[0]).toEqual(metric);
      });

      it('should add multiple performance metrics', () => {
        for (let i = 0; i < 5; i++) {
          testLogger.addPerformanceMetric({
            timestamp: new Date(),
            operation: `op-${i}`,
            duration: i * 100,
            success: true,
          });
        }

        const metrics = testLogger.getPerformanceMetrics();
        expect(metrics).toHaveLength(5);
      });

      it('should limit metrics to 1000 entries', () => {
        // Add 1100 metrics
        for (let i = 0; i < 1100; i++) {
          testLogger.addPerformanceMetric({
            timestamp: new Date(),
            operation: `op-${i}`,
            duration: 100,
            success: true,
          });
        }

        const metrics = testLogger.getPerformanceMetrics(24); // Get all within 24 hours
        expect(metrics.length).toBeLessThanOrEqual(1000);
      });

      it('should get metrics within time window', () => {
        const now = Date.now();

        // Add old metric (2 hours ago)
        testLogger.addPerformanceMetric({
          timestamp: new Date(now - 2 * 60 * 60 * 1000),
          operation: 'old-op',
          duration: 100,
          success: true,
        });

        // Add recent metric (30 minutes ago)
        testLogger.addPerformanceMetric({
          timestamp: new Date(now - 30 * 60 * 1000),
          operation: 'recent-op',
          duration: 100,
          success: true,
        });

        // Get metrics from last 1 hour
        const metrics = testLogger.getPerformanceMetrics(1);

        expect(metrics).toHaveLength(1);
        expect(metrics[0].operation).toBe('recent-op');
      });

      it('should return empty array when no metrics in time window', () => {
        // Add old metric (3 hours ago)
        testLogger.addPerformanceMetric({
          timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000),
          operation: 'old-op',
          duration: 100,
          success: true,
        });

        // Get metrics from last 1 hour
        const metrics = testLogger.getPerformanceMetrics(1);

        expect(metrics).toHaveLength(0);
      });

      it('should cleanup old metrics', () => {
        const now = Date.now();

        // Add old metrics (2 hours ago)
        for (let i = 0; i < 3; i++) {
          testLogger.addPerformanceMetric({
            timestamp: new Date(now - 2 * 60 * 60 * 1000),
            operation: `old-op-${i}`,
            duration: 100,
            success: true,
          });
        }

        // Add recent metrics (30 minutes ago)
        for (let i = 0; i < 2; i++) {
          testLogger.addPerformanceMetric({
            timestamp: new Date(now - 30 * 60 * 1000),
            operation: `recent-op-${i}`,
            duration: 100,
            success: true,
          });
        }

        expect(testLogger.getPerformanceMetrics(24)).toHaveLength(5);

        testLogger.cleanup();

        const metricsAfterCleanup = testLogger.getPerformanceMetrics(24);
        expect(metricsAfterCleanup).toHaveLength(2);
        expect(metricsAfterCleanup.every((m: { operation: string }) => m.operation.startsWith('recent'))).toBe(true);
      });

      it('should handle failed operations in metrics', () => {
        testLogger.addPerformanceMetric({
          timestamp: new Date(),
          operation: 'failed-op',
          duration: 500,
          success: false,
          errorMessage: 'Operation failed',
        });

        const metrics = testLogger.getPerformanceMetrics();
        expect(metrics[0].success).toBe(false);
        expect(metrics[0].errorMessage).toBe('Operation failed');
      });
    });
  });

  describe('PerformanceTimer', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should track operation duration for successful operation', () => {
      const timer = new PerformanceTimer('timer-test-op');

      jest.advanceTimersByTime(150);

      timer.end(true);

      // PerformanceTimer uses the global securityLogger instance
      const metrics = securityLogger.getPerformanceMetrics();
      const testMetric = metrics.find((m) => m.operation === 'timer-test-op');
      expect(testMetric).toBeDefined();
      expect(testMetric!.duration).toBe(150);
      expect(testMetric!.success).toBe(true);
    });

    it('should track operation duration for failed operation', () => {
      const timer = new PerformanceTimer('timer-failing-op');

      jest.advanceTimersByTime(300);

      timer.end(false, 'Operation timeout');

      const metrics = securityLogger.getPerformanceMetrics();
      const testMetric = metrics.find((m) => m.operation === 'timer-failing-op');
      expect(testMetric).toBeDefined();
      expect(testMetric!.duration).toBe(300);
      expect(testMetric!.success).toBe(false);
      expect(testMetric!.errorMessage).toBe('Operation timeout');
    });

    it('should log debug message on timer start', () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const timer = new PerformanceTimer('debug-operation');

      expect(mockWinstonLogger.debug).toHaveBeenCalledWith('Starting: debug-operation', undefined);
    });

    it('should log debug message on successful completion', () => {
      const timer = new PerformanceTimer('successful-op');

      jest.advanceTimersByTime(200);

      timer.end(true);

      expect(mockWinstonLogger.debug).toHaveBeenCalledWith('Completed: successful-op (200ms)', undefined);
    });

    it('should log warn message on failed completion', () => {
      const timer = new PerformanceTimer('failed-op');

      jest.advanceTimersByTime(250);

      timer.end(false, 'Error occurred');

      expect(mockWinstonLogger.warn).toHaveBeenCalledWith('Failed: failed-op (250ms)', {
        errorMessage: 'Error occurred',
      });
    });

    it('should track multiple concurrent operations', () => {
      const timer1 = new PerformanceTimer('timer-concurrent-1');
      jest.advanceTimersByTime(100);

      const timer2 = new PerformanceTimer('timer-concurrent-2');
      jest.advanceTimersByTime(50);

      timer1.end(true);
      jest.advanceTimersByTime(100);

      timer2.end(true);

      const metrics = securityLogger.getPerformanceMetrics();
      const op1 = metrics.find((m) => m.operation === 'timer-concurrent-1');
      const op2 = metrics.find((m) => m.operation === 'timer-concurrent-2');

      expect(op1).toBeDefined();
      expect(op1!.duration).toBe(150);
      expect(op2).toBeDefined();
      expect(op2!.duration).toBe(150);
    });
  });
});
