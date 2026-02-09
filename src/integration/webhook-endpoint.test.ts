/**
 * Integration Tests: Webhook Endpoint
 * Tests the full HTTP webhook endpoint with supertest.
 * Verifies validation handshake, clientState, and notification acceptance.
 */

import './setup.js';
import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createWebhookRouter } from '../services/webhook-route.js';

const CLIENT_STATE = 'integration-test-secret';

function createTestApp(): express.Application {
  const app = express();
  app.use(express.json());
  app.use(createWebhookRouter(CLIENT_STATE));
  return app;
}

function validPayload(clientState = CLIENT_STATE) {
  return {
    value: [
      {
        subscriptionId: 'sub-integration-1',
        clientState,
        changeType: 'created',
        resource: 'users/mailbox/messages/msg-int-1',
        resourceData: { '@odata.id': 'odata-1', id: 'msg-int-1' },
      },
    ],
  };
}

describe('Webhook Endpoint Integration', () => {
  let app: express.Application;

  beforeEach(() => {
    app = createTestApp();
  });

  describe('validation handshake', () => {
    it('should return validation token for Graph API handshake', async () => {
      const res = await request(app)
        .post('/webhooks/mail?validationToken=test-token-abc123')
        .expect(200)
        .expect('Content-Type', /text\/plain/);

      expect(res.text).toBe('test-token-abc123');
    });

    it('should reject tokens with unsafe characters', async () => {
      await request(app).post('/webhooks/mail?validationToken=<script>alert(1)</script>').expect(400);
    });
  });

  describe('clientState validation', () => {
    it('should reject notifications with wrong clientState', async () => {
      await request(app).post('/webhooks/mail').send(validPayload('wrong-secret')).expect(403);
    });

    it('should accept notifications with correct clientState', async () => {
      await request(app).post('/webhooks/mail').send(validPayload()).expect(202);
    });
  });

  describe('payload validation', () => {
    it('should reject empty body', async () => {
      await request(app).post('/webhooks/mail').send({}).expect(400);
    });

    it('should reject payload with empty value array', async () => {
      await request(app).post('/webhooks/mail').send({ value: [] }).expect(400);
    });
  });

  describe('notification acceptance', () => {
    it('should return 202 with accepted status for valid notification', async () => {
      const res = await request(app).post('/webhooks/mail').send(validPayload()).expect(202);

      expect(res.body).toEqual({ status: 'accepted' });
    });

    it('should accept payload with multiple notifications', async () => {
      const payload = {
        value: [
          {
            subscriptionId: 's1',
            clientState: CLIENT_STATE,
            changeType: 'created',
            resource: 'r1',
            resourceData: { '@odata.id': 'o1', id: 'msg-a' },
          },
          {
            subscriptionId: 's1',
            clientState: CLIENT_STATE,
            changeType: 'created',
            resource: 'r2',
            resourceData: { '@odata.id': 'o2', id: 'msg-b' },
          },
        ],
      };

      const res = await request(app).post('/webhooks/mail').send(payload).expect(202);

      expect(res.body).toEqual({ status: 'accepted' });
    });
  });
});
