/**
 * Standardized error handling utilities
 */

/** Safely convert unknown caught value to an Error instance */
export function toError(err: unknown): Error {
  if (err instanceof Error) return err;
  return new Error(String(err));
}

/** Extract error message string from unknown caught value */
export function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
