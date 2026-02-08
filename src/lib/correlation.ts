/**
 * Correlation Context
 * Provides end-to-end correlation IDs for tracing email processing lifecycle.
 * Uses AsyncLocalStorage to propagate context through async operations.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

/** Correlation context carried through async operations */
export interface CorrelationContext {
  correlationId: string;
  /** Timestamp (ms) when the email arrived (webhook notification or poll) */
  arrivalTimestamp: number;
  /** Current processing stage */
  stage: ProcessingStage;
}

/** Processing stages for lifecycle tracking */
export type ProcessingStage =
  | 'arrival'
  | 'guard-check'
  | 'email-fetch'
  | 'threat-intel'
  | 'llm-analysis'
  | 'risk-scoring'
  | 'reply-send'
  | 'completed'
  | 'rejected';

const storage = new AsyncLocalStorage<CorrelationContext>();

/** Generate a new correlation ID */
export function generateCorrelationId(): string {
  return `corr-${randomUUID()}`;
}

/** Get the current correlation context (if any) */
export function getCorrelationContext(): CorrelationContext | undefined {
  return storage.getStore();
}

/** Get the current correlation ID, or 'none' if not in a context */
export function getCorrelationId(): string {
  return storage.getStore()?.correlationId ?? 'none';
}

/** Update the current processing stage */
export function setProcessingStage(stage: ProcessingStage): void {
  const ctx = storage.getStore();
  if (ctx) {
    ctx.stage = stage;
  }
}

/** Run a function within a new correlation context */
export function runWithCorrelation<T>(correlationId: string, fn: () => T): T {
  const context: CorrelationContext = {
    correlationId,
    arrivalTimestamp: Date.now(),
    stage: 'arrival',
  };
  return storage.run(context, fn);
}

/** Run a function within an existing correlation context */
export function runWithExistingCorrelation<T>(context: CorrelationContext, fn: () => T): T {
  return storage.run(context, fn);
}
