# Runbook: Threat Intel Service Failure

## Symptoms

- "Threat intel enrichment failed" warnings in logs
- Risk scores lower than expected (missing IP/URL reputation data)
- `/health/deep` shows `threatIntel: false`
- Increased false negatives (phishing emails scored below threshold)

## Fallback Behavior

The agent is designed for graceful degradation. When threat intel fails:

- **Analysis continues** — SPF/DKIM/DMARC, content analysis, and attachment checks are unaffected
- **Risk scores may be lower** — no IP reputation or URL blocklist data is added
- **No errors are thrown** — `enrichWithThreatIntel()` returns `{ indicators: [], riskContribution: 0 }`
- **LLM analysis still runs** — if enabled and risk score meets threshold

**Impact assessment:** Threat intel typically adds 0-3 points to risk scores. Emails that rely on reputation data for detection may be missed.

## Diagnosis

### 1. Check health endpoint

```bash
curl -s -H "Authorization: Bearer $API_KEY" https://<app>/health/deep | jq '.threatIntel'
```

### 2. Check VirusTotal

```bash
# Test API key validity
curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/urls" | jq '.error'

# Check rate limit headers
curl -s -I -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8" | grep -i x-api
```

- Free tier: 4 requests/minute, 500 requests/day
- Premium tier: higher limits per contract

### 3. Check AbuseIPDB

```bash
# Test API key validity
curl -s -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json" \
  "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" | jq '.errors'
```

- Free tier: 1,000 checks/day
- Check remaining quota in response headers

### 4. Check Key Vault access

If API keys are stored in Azure Key Vault:

```bash
# Test Key Vault connectivity
az keyvault secret show --vault-name <vault> --name VIRUSTOTAL-API-KEY --query value -o tsv
az keyvault secret show --vault-name <vault> --name ABUSEIPDB-API-KEY --query value -o tsv
```

### 5. Check network connectivity

```bash
# From within the container
curl -s -o /dev/null -w "%{http_code}" https://www.virustotal.com/api/v3/
curl -s -o /dev/null -w "%{http_code}" https://api.abuseipdb.com/api/v2/
```

## Resolution

| Issue                  | Fix                                                |
| ---------------------- | -------------------------------------------------- |
| API key expired        | Rotate key in Key Vault, restart app               |
| Rate limit exceeded    | Wait for reset or upgrade tier                     |
| Key Vault inaccessible | Check managed identity permissions, network rules  |
| Network blocked        | Check NSG rules, Container Apps egress settings    |
| API service down       | Wait for recovery — fallback behavior is automatic |

## Long-Term Mitigations

- Set up alerting on consecutive threat intel failures (>10 in 1 hour)
- Cache threat intel results to reduce API calls (results are cached with configurable TTL)
- Consider adding a secondary threat intel provider for redundancy
- Monitor API quota usage and upgrade tiers before hitting limits
