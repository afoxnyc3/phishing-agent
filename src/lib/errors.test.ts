import { describe, it, expect } from '@jest/globals';
import { toError, getErrorMessage } from './errors.js';

describe('Error Utilities', () => {
  describe('toError', () => {
    it('should return Error instances unchanged', () => {
      const err = new Error('test');
      expect(toError(err)).toBe(err);
    });

    it('should wrap string in Error', () => {
      const result = toError('something failed');
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('something failed');
    });

    it('should wrap null', () => {
      expect(toError(null).message).toBe('null');
    });

    it('should wrap undefined', () => {
      expect(toError(undefined).message).toBe('undefined');
    });

    it('should wrap numbers', () => {
      expect(toError(404).message).toBe('404');
    });

    it('should wrap objects', () => {
      const result = toError({ code: 'FAIL' });
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('[object Object]');
    });

    it('should preserve Error subclasses', () => {
      const err = new TypeError('bad type');
      expect(toError(err)).toBe(err);
      expect(toError(err)).toBeInstanceOf(TypeError);
    });
  });

  describe('getErrorMessage', () => {
    it('should extract message from Error', () => {
      expect(getErrorMessage(new Error('test'))).toBe('test');
    });

    it('should convert string to message', () => {
      expect(getErrorMessage('failed')).toBe('failed');
    });

    it('should handle null', () => {
      expect(getErrorMessage(null)).toBe('null');
    });

    it('should handle undefined', () => {
      expect(getErrorMessage(undefined)).toBe('undefined');
    });

    it('should handle numbers', () => {
      expect(getErrorMessage(500)).toBe('500');
    });

    it('should handle objects', () => {
      expect(getErrorMessage({ error: true })).toBe('[object Object]');
    });
  });
});
