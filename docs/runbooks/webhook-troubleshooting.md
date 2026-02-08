# Runbook: Webhook Subscription Troubleshooting

## Symptoms

- No new emails processed despite inbox activity
- Timer fallback catching all emails (webhook miss rate near 100%)
- "Subscription expired" or "subscriptionRemoved" warnings in logs
- `POST /webhooks/mail` receiving no traffic

## Detection

```bash
# Check health endpoint for webhook status
curl -s -H "Authorization: Bearer $API_KEY" https://<app>/health/deep | jq '.webhook'

# Compare processing sources
# If timer fallback processes >> webhook, webhooks are failing
```

## Diagnosis Steps

### 1. Check subscription status

```bash
# List active Graph API subscriptions
# Requires Application.ReadWrite.All or Subscription.Read.All permission
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/subscriptions" \
  --headers "Content-Type=application/json"
```

Look for a subscription with:

- `resource`: `users/{PHISHING_MAILBOX_ADDRESS}/messages`
- `changeType`: `created`
- `expirationDateTime`: must be in the future

### 2. Verify notification URL is reachable

```bash
# Test from external network
curl -s -o /dev/null -w "%{http_code}" \
  "https://<app>/webhooks/mail?validationToken=test"
# Expected: 200 with "test" in body
```

### 3. Check subscription expiry

Graph API mail subscriptions expire after **3 days maximum**. The subscription manager should auto-renew every 2 days. If renewal failed:

- Check for auth token refresh failures in logs
- Verify `AZURE_CLIENT_SECRET` hasn't expired
- Check Microsoft Graph service health

### 4. Verify clientState match

The `WEBHOOK_CLIENT_STATE` environment variable must match the `clientState` set during subscription creation. A mismatch causes all notifications to return 403.

## Resolution

### Recreate subscription

If the subscription is missing or expired, restart the application — subscription creation runs on startup.

```bash
# Azure Container Apps
az containerapp revision restart --name phishing-agent --resource-group <rg>
```

### Fix notification URL

If the URL is unreachable:

1. Check Azure Container Apps ingress settings (must allow external traffic)
2. Verify custom domain DNS if applicable
3. Check that TLS certificate is valid (Graph API requires HTTPS)

### Rotate clientState

If clientState may be compromised:

1. Generate a new random secret
2. Update `WEBHOOK_CLIENT_STATE` environment variable
3. Restart the application (recreates subscription with new clientState)

## Fallback

While webhook issues are being resolved:

- **Timer fallback** (hourly) remains active and catches missed emails
- **Polling** can be re-enabled: set `POLLING_ENABLED=true`
- No emails are lost — dedup layer prevents double-processing once webhooks recover
