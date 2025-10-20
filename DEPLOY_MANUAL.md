# Manual Azure Deployment Guide

**Quick deployment guide for getting phishing-agent to production in Azure Container Apps.**

**Time estimate:** 30-45 minutes
**Cost estimate:** ~$30-50/month

---

## Prerequisites

- ✅ Docker image built locally (`phishing-agent:latest`)
- ✅ Azure CLI installed (`az --version`)
- ✅ Azure subscription with Contributor access
- ✅ Valid Azure AD credentials in `.env` file

---

## Step 1: Azure Login & Setup (5 min)

### Login to Azure
```bash
# Login to Azure
az login

# List subscriptions
az account list --output table

# Set active subscription (if you have multiple)
az account set --subscription "Your Subscription Name"

# Verify active subscription
az account show
```

### Create Resource Group
```bash
# Create resource group in East US
az group create \
  --name rg-phishing-agent \
  --location eastus

# Verify creation
az group show --name rg-phishing-agent
```

---

## Step 2: Create Azure Container Registry (10 min)

### Create ACR
```bash
# Create container registry (Basic SKU for MVP)
az acr create \
  --resource-group rg-phishing-agent \
  --name phishingagentacr \
  --sku Basic \
  --admin-enabled true

# Login to ACR
az acr login --name phishingagentacr

# Get ACR login server
az acr show \
  --name phishingagentacr \
  --query loginServer \
  --output tsv
```

**Note:** ACR name must be globally unique. If `phishingagentacr` is taken, try `phishingagent<yourname>` or `phishingagent<random>`.

### Push Docker Image to ACR
```bash
# Tag local image for ACR
docker tag phishing-agent:latest phishingagentacr.azurecr.io/phishing-agent:v0.2.0
docker tag phishing-agent:latest phishingagentacr.azurecr.io/phishing-agent:latest

# Push to ACR
docker push phishingagentacr.azurecr.io/phishing-agent:v0.2.0
docker push phishingagentacr.azurecr.io/phishing-agent:latest

# Verify image in registry
az acr repository list --name phishingagentacr --output table
az acr repository show-tags --name phishingagentacr --repository phishing-agent --output table
```

---

## Step 3: Create Container Apps Environment (5 min)

### Install Container Apps Extension
```bash
# Add Container Apps extension (if not already installed)
az extension add --name containerapp --upgrade
```

### Create Container Apps Environment
```bash
# Create Container Apps environment
az containerapp env create \
  --name cae-phishing-agent \
  --resource-group rg-phishing-agent \
  --location eastus

# Verify creation
az containerapp env show \
  --name cae-phishing-agent \
  --resource-group rg-phishing-agent
```

---

## Step 4: Deploy Container App (15 min)

### Get ACR Credentials
```bash
# Get ACR password for authentication
az acr credential show --name phishingagentacr

# Save these for the next step:
# - Username: phishingagentacr
# - Password: <use password from output>
```

### Prepare Environment Variables

From your `.env` file, extract:
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `PHISHING_MAILBOX_ADDRESS`

### Create Container App
```bash
# Create container app with environment variables
az containerapp create \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --environment cae-phishing-agent \
  --image phishingagentacr.azurecr.io/phishing-agent:v0.2.0 \
  --target-port 3000 \
  --ingress external \
  --registry-server phishingagentacr.azurecr.io \
  --registry-username phishingagentacr \
  --registry-password "<password-from-previous-step>" \
  --cpu 0.5 \
  --memory 1Gi \
  --min-replicas 1 \
  --max-replicas 3 \
  --env-vars \
    "AZURE_TENANT_ID=<your-tenant-id>" \
    "AZURE_CLIENT_ID=<your-client-id>" \
    "AZURE_CLIENT_SECRET=<your-client-secret>" \
    "PHISHING_MAILBOX_ADDRESS=<your-mailbox>" \
    "MAILBOX_CHECK_INTERVAL_MS=60000" \
    "MAILBOX_MONITOR_ENABLED=true" \
    "NODE_ENV=production" \
    "PORT=3000" \
    "LOG_LEVEL=info"
```

**Security Note:** For production, use `--secrets` instead of `--env-vars` for sensitive data:
```bash
# Alternative secure approach (recommended)
az containerapp create \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --environment cae-phishing-agent \
  --image phishingagentacr.azurecr.io/phishing-agent:v0.2.0 \
  --target-port 3000 \
  --ingress external \
  --registry-server phishingagentacr.azurecr.io \
  --registry-username phishingagentacr \
  --registry-password "<password>" \
  --cpu 0.5 \
  --memory 1Gi \
  --min-replicas 1 \
  --max-replicas 3 \
  --secrets \
    azure-client-secret="<your-client-secret>" \
  --env-vars \
    "AZURE_TENANT_ID=<your-tenant-id>" \
    "AZURE_CLIENT_ID=<your-client-id>" \
    "AZURE_CLIENT_SECRET=secretref:azure-client-secret" \
    "PHISHING_MAILBOX_ADDRESS=<your-mailbox>" \
    "MAILBOX_CHECK_INTERVAL_MS=60000" \
    "MAILBOX_MONITOR_ENABLED=true" \
    "NODE_ENV=production" \
    "PORT=3000" \
    "LOG_LEVEL=info"
```

---

## Step 5: Verify Deployment (5 min)

### Get Application URL
```bash
# Get the FQDN (Fully Qualified Domain Name)
az containerapp show \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --query properties.configuration.ingress.fqdn \
  --output tsv

# Save this URL - it's your production endpoint!
```

### Test Health Endpoints
```bash
# Test health endpoint (replace <url> with your FQDN)
curl https://<your-fqdn>/health

# Expected response:
# {"status":"healthy","timestamp":"2025-10-19T...","uptime":...}

# Test ready endpoint
curl https://<your-fqdn>/ready

# Expected response:
# {"status":"ready","timestamp":"...","phishingAgent":true,"mailboxMonitor":true}
```

### Check Application Logs
```bash
# View live logs
az containerapp logs show \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --follow

# Look for:
# - "Phishing Agent initialized successfully"
# - "HTTP server started"
# - "Mailbox monitor started successfully"
# - No errors
```

### Check Container Status
```bash
# Get container app status
az containerapp show \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --query properties.runningStatus

# Should show: "Running"

# Get revision details
az containerapp revision list \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --output table
```

---

## Step 6: Test with Real Email (15 min)

### Send Test Phishing Email

1. **Find a real phishing email** (from spam folder, PhishTank, etc.)
2. **Forward it** to your monitored mailbox (e.g., phishing@chelseapiers.com)
3. **Wait 60 seconds** (mailbox polling interval)
4. **Check logs** for analysis activity:
   ```bash
   az containerapp logs show \
     --name phishing-agent \
     --resource-group rg-phishing-agent \
     --follow
   ```

### Expected Log Output
```
info: Mailbox monitor checking for new emails
info: Found 1 new email(s)
info: Starting email analysis
info: Phishing analysis complete (score: 8.5, severity: HIGH)
info: Sending analysis reply to user
info: Analysis reply sent successfully
```

### Verify Reply Email

Check the sender's inbox (whoever forwarded the email) for:
- Subject: `Re: [Original Subject] - Analysis Results`
- HTML-formatted risk assessment
- Risk score and severity
- Threat indicators
- Recommended actions

---

## Step 7: Monitor and Maintain

### View Metrics
```bash
# Get replica count and status
az containerapp replica list \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --output table

# Get ingress traffic
az containerapp ingress traffic show \
  --name phishing-agent \
  --resource-group rg-phishing-agent
```

### Update Container App
```bash
# If you need to update environment variables
az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --set-env-vars "NEW_VAR=value"

# If you need to deploy new image
docker push phishingagentacr.azurecr.io/phishing-agent:v0.2.1

az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --image phishingagentacr.azurecr.io/phishing-agent:v0.2.1
```

### Scale Container App
```bash
# Manually scale replicas
az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --min-replicas 2 \
  --max-replicas 5

# Update resource limits
az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --cpu 1.0 \
  --memory 2Gi
```

---

## Troubleshooting

### Container Won't Start
```bash
# Check logs for errors
az containerapp logs show \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --tail 50

# Common issues:
# - Missing environment variables
# - Invalid Azure credentials
# - Mailbox authentication failure
```

### Health Checks Failing
```bash
# SSH into container (if needed)
az containerapp exec \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --command /bin/sh

# Check port binding
netstat -tulpn | grep 3000
```

### Mailbox Monitor Not Working
Check logs for:
- `Access is denied` → Invalid Azure credentials
- `Mailbox not found` → Wrong mailbox address
- `Timeout` → Network/firewall issue

---

## Cost Management

### Current Configuration Cost Estimate:
- **Container Apps**: ~$25-30/month (1 replica, 0.5 vCPU, 1Gi RAM)
- **Container Registry**: ~$5/month (Basic SKU)
- **Total**: ~$30-35/month

### Cost Optimization Tips:
```bash
# Stop container app when not in use
az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --min-replicas 0 \
  --max-replicas 0

# Restart when needed
az containerapp update \
  --name phishing-agent \
  --resource-group rg-phishing-agent \
  --min-replicas 1 \
  --max-replicas 3
```

---

## Cleanup (If Needed)

### Delete Everything
```bash
# Delete entire resource group (removes all resources)
az group delete --name rg-phishing-agent --yes --no-wait

# Or delete individual resources
az containerapp delete --name phishing-agent --resource-group rg-phishing-agent --yes
az acr delete --name phishingagentacr --resource-group rg-phishing-agent --yes
```

---

## Success Checklist

After deployment, verify:

- [ ] Container app is running (`az containerapp show`)
- [ ] Health endpoint returns 200 OK
- [ ] Ready endpoint shows all services healthy
- [ ] Logs show "Phishing Agent is running"
- [ ] Mailbox monitor is polling successfully
- [ ] Test email forwarded and analyzed
- [ ] Reply email received with analysis
- [ ] No errors in logs
- [ ] Production URL documented
- [ ] Cost alerts configured

---

## Next Steps

Once deployed and validated:

1. **Monitor for 1 week**
   - Track emails processed
   - Measure accuracy (true/false positives)
   - Collect user feedback

2. **Document findings**
   - What works well?
   - What needs improvement?
   - User satisfaction?

3. **Decide next phase**
   - If successful → Add CI/CD automation
   - If issues → Iterate and redeploy
   - If not valuable → Pivot or sunset

---

## Reference

**Production URL:** `https://<your-fqdn>` (from Step 5)
**Resource Group:** `rg-phishing-agent`
**Container App:** `phishing-agent`
**Container Registry:** `phishingagentacr.azurecr.io`
**Location:** `eastus`

**Deployment Date:** <!-- Add date -->
**Deployed By:** <!-- Add name -->
**Version:** v0.2.0
