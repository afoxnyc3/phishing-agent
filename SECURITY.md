# Security Guide

**Purpose**: This document outlines security best practices, credential management, and incident response procedures for the phishing-agent project.

**Last Updated**: 2025-10-20
**Version**: v0.2.2

**Note**: Adapt these security procedures to your organization's specific requirements and policies.

---

## Credential Management

### Azure Credentials

**Required Credentials**:
- `AZURE_TENANT_ID` - Your Azure AD tenant ID
- `AZURE_CLIENT_ID` - Application (client) ID from App Registration
- `AZURE_CLIENT_SECRET` - Client secret from App Registration

**Security Requirements**:
- ✅ Store credentials ONLY in `.env` file (already in `.gitignore`)
- ✅ Never commit credentials to git
- ✅ Rotate client secrets every 90 days
- ✅ Use Azure Key Vault for production deployments
- ✅ Use Managed Identity when deploying to Azure

### Threat Intel API Keys (Optional)

**Optional Keys**:
- `VIRUSTOTAL_API_KEY` - VirusTotal API key
- `ABUSEIPDB_API_KEY` - AbuseIPDB API key
- `URLSCAN_API_KEY` - URLScan.io API key

**Security Requirements**:
- ✅ Store in `.env` file
- ✅ Use separate keys for dev/staging/production
- ✅ Monitor API usage for anomalies
- ✅ Rotate if exposed

---

## Credential Rotation Guide

### When to Rotate Credentials

**Immediate rotation required if**:
- Credentials committed to git history
- Credentials shared in unsecure channel (email, chat)
- Suspicious activity detected in logs
- Team member with access leaves organization
- Security audit recommends rotation

**Scheduled rotation**:
- Azure client secrets: Every 90 days
- API keys: Every 180 days or per provider policy

### How to Rotate Azure Client Secret

#### 1. Create New Client Secret

```bash
# Azure Portal method:
# 1. Go to Azure Portal → Azure Active Directory
# 2. Navigate to App Registrations → Your App → Certificates & secrets
# 3. Click "New client secret"
# 4. Set description: "Phishing Agent Production - 2025-Q2"
# 5. Set expiration: 90 days (recommended) or custom
# 6. Click "Add"
# 7. IMMEDIATELY copy the secret value (shown only once)

# Azure CLI method:
az ad app credential reset \
  --id <AZURE_CLIENT_ID> \
  --append \
  --display-name "Phishing Agent Production - 2025-Q2" \
  --years 0.25
```

#### 2. Update Environment Variables

```bash
# Update .env file with new secret
# DO NOT delete old secret from Azure yet (allows rollback)
AZURE_CLIENT_SECRET=<new-secret-value>
```

#### 3. Test Authentication

```bash
# Start the application in test mode
npm run dev

# Verify successful authentication in logs
# Look for: "Mailbox monitor started successfully"
# Look for: "Successfully connected to mailbox"
```

#### 4. Deploy to Production

```bash
# Update production environment variables
# Azure Container Apps:
az containerapp update \
  --name phishing-agent \
  --resource-group rg-security \
  --set-env-vars AZURE_CLIENT_SECRET=<new-secret>

# Docker:
# Update .env file on production server and restart container
docker-compose down && docker-compose up -d
```

#### 5. Verify Production

```bash
# Check health endpoint
curl https://your-production-url.com/health

# Check readiness endpoint
curl https://your-production-url.com/ready

# Monitor logs for any authentication errors
```

#### 6. Delete Old Client Secret

```bash
# After 24-48 hours of successful operation with new secret
# Azure Portal → App Registrations → Your App → Certificates & secrets
# Delete old secret

# Or via Azure CLI:
az ad app credential delete \
  --id <AZURE_CLIENT_ID> \
  --key-id <old-credential-key-id>
```

### How to Rotate API Keys

For VirusTotal, AbuseIPDB, URLScan:

1. Generate new API key from provider dashboard
2. Update `.env` file with new key
3. Restart application
4. Verify threat intel enrichment works (check logs)
5. Delete old API key from provider dashboard after 24 hours

---

## Incident Response

### Credential Exposure in Git History

**If credentials were committed to git**:

```bash
# 1. Verify exposure
git log --all --full-history -- .env
git log --all -S "AZURE_CLIENT_SECRET" --source --all

# 2. IMMEDIATELY rotate all exposed credentials
# Follow rotation guide above

# 3. Remove from git history (if repo is not public)
# WARNING: This rewrites history, coordinate with team
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all

# Push force (only if necessary and coordinated)
git push origin --force --all

# 4. Clean local repo
rm -rf .git/refs/original/
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# 5. Notify team to re-clone repository
```

**If repository is public**:
- Assume all credentials are compromised
- Rotate ALL credentials immediately
- Consider the repository permanently tainted
- Audit all Azure resources for unauthorized access

### Suspicious Activity Detection

**Signs of compromised credentials**:
- Unexpected API calls in Azure logs
- Emails sent from mailbox outside normal hours
- Failed authentication attempts
- Unusual Graph API usage patterns

**Response steps**:
1. Immediately rotate all credentials
2. Review Azure AD sign-in logs
3. Review Graph API audit logs
4. Check for unauthorized mailbox rules
5. Scan for malicious emails sent from compromised mailbox
6. Update incident response plan

---

## Security Best Practices

### Development

- ✅ Use `.env` file for local development (never commit)
- ✅ Use `.env.example` for documentation (no real values)
- ✅ Add all credential files to `.gitignore`
- ✅ Never hardcode credentials in source code
- ✅ Never log credentials (even masked)
- ✅ Use pre-commit hooks to scan for secrets

### Production

- ✅ Use Azure Key Vault or equivalent secret management
- ✅ Use Managed Identity when possible (eliminates client secrets)
- ✅ Enable Azure AD Conditional Access policies
- ✅ Monitor authentication logs daily
- ✅ Set up alerts for failed authentication
- ✅ Implement least-privilege permissions

### Code Review Checklist

Before merging any PR:
- [ ] No credentials in code or config files
- [ ] No credentials in commit messages
- [ ] All new config uses environment variables
- [ ] No sensitive data in logs
- [ ] Security tests pass

---

## Audit Log Template

Track all credential rotations in your organization:

| Date | Credential Type | Reason | Performed By | Notes |
|------|----------------|--------|--------------|-------|
| YYYY-MM-DD | Azure Client Secret | Scheduled 90-day rotation | Admin Name | Successful |
| YYYY-MM-DD | API Keys | Security incident response | Admin Name | Emergency rotation |
| | | | | |

**Best Practices**:
- Log all credential changes
- Include who performed the rotation
- Document the reason (scheduled vs. incident)
- Note any issues encountered
- Review audit log monthly

---

## Additional Resources

- [Azure AD App Registration Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Microsoft Graph API Security Best Practices](https://learn.microsoft.com/en-us/graph/security-authorization)

---

## Contact

For security issues or questions:
- **Email**: security@yourcompany.com
- **Internal Communication**: Use your organization's secure channel (e.g., Slack #security-team)
- **Emergency**: Follow your organization's incident response procedures

**For Public Vulnerability Reports**:
- Use GitHub Security Advisories (https://github.com/YOUR-REPO/security/advisories)
- Or email security contact listed in repository
