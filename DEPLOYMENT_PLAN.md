# Deployment Infrastructure Plan

**Project:** Phishing Agent
**Version:** v0.3.0 (Deployment Infrastructure)
**Date:** 2025-10-19
**Status:** Planning Phase

---

## Executive Summary

This document outlines the complete deployment infrastructure implementation for the phishing-agent project. The goal is to containerize the application, automate testing and deployment via CI/CD, and enable production deployment to Azure Container Apps.

**Target completion:** 2-3 hours of focused implementation
**Risk level:** Low (non-breaking changes to existing codebase)

---

## Current State Analysis

### ✅ Strengths
- Production-ready codebase with 95.82% test coverage
- Clean build process (TypeScript → 336KB dist output)
- Health check endpoints (`/health`, `/ready`)
- Graceful shutdown handling (SIGTERM, SIGINT)
- Structured logging with Winston
- Zod runtime validation for production safety
- ES modules with path aliases

### ❌ Gaps
- No Docker containerization
- No CI/CD pipeline
- No automated deployment
- No container registry integration
- No production deployment documentation

---

## Implementation Phases

### Phase 1: Docker Containerization (Est: 45 min)

**Objective:** Create optimized, production-ready Docker container

#### 1.1 Dockerfile (Multi-stage Build)

**File:** `Dockerfile`
**Target image size:** 60-80MB

**Strategy:**
- Multi-stage build to minimize final image size
- Builder stage: Compile TypeScript, install all dependencies
- Production stage: Copy compiled code, install production deps only
- Alpine Linux base for minimal footprint
- Non-root user for security

**Structure:**
```dockerfile
# Stage 1: Builder
FROM node:18-alpine AS builder
- Install all dependencies (including devDependencies)
- Copy source code
- Compile TypeScript (npm run build)
- Run tsc-alias for path mapping

# Stage 2: Production
FROM node:18-alpine AS production
- Copy package.json and package-lock.json
- Install production dependencies only (npm ci --only=production)
- Copy compiled dist/ from builder
- Create non-root user (appuser)
- Switch to non-root user
- Expose port 3000
- Health check via /health endpoint
- CMD: node dist/index.js
```

**Security features:**
- Non-root user execution
- Minimal attack surface (Alpine)
- No source code in final image
- No development dependencies

#### 1.2 .dockerignore

**File:** `.dockerignore`

**Excludes:**
- Development files: `*.test.ts`, `coverage/`, `.vscode/`, `.idea/`
- Build artifacts: `dist/`, `node_modules/`, `*.tsbuildinfo`
- Git metadata: `.git/`, `.gitignore`
- Documentation: `*.md` (except README.md for image metadata)
- Environment: `.env`, `.env.*`
- Logs: `logs/`, `*.log`
- OS files: `.DS_Store`, `Thumbs.db`
- Security: `SECURITY.md`, `test-graph-auth.js`

**Purpose:** Reduce build context, faster builds, smaller layers

#### 1.3 docker-compose.yml (Local Development)

**File:** `docker-compose.yml`

**Services:**
- `phishing-agent`: Main application service

**Configuration:**
- Build from local Dockerfile
- Environment variables from `.env` file
- Port mapping: `3000:3000`
- Restart policy: `unless-stopped`
- Health check: `curl -f http://localhost:3000/health`
- Logging: JSON driver with max size/files

**Usage:**
```bash
# Start service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop service
docker-compose down
```

#### 1.4 Local Testing Checklist

- [ ] Build Docker image: `docker build -t phishing-agent:local .`
- [ ] Verify image size: `docker images phishing-agent:local`
- [ ] Run container: `docker run --env-file .env -p 3000:3000 phishing-agent:local`
- [ ] Test health endpoint: `curl http://localhost:3000/health`
- [ ] Test ready endpoint: `curl http://localhost:3000/ready`
- [ ] Verify logs: `docker logs <container-id>`
- [ ] Test graceful shutdown: `docker stop <container-id>` (should log shutdown)
- [ ] Test with docker-compose: `docker-compose up`

---

### Phase 2: CI/CD Pipeline (Est: 60 min)

**Objective:** Automate testing, building, and quality checks

#### 2.1 GitHub Actions CI Workflow

**File:** `.github/workflows/ci.yml`

**Triggers:**
- Push to `main` branch
- Pull requests to `main`
- Manual workflow dispatch (for testing)

**Jobs:**

**Job 1: Lint**
- Checkout code
- Setup Node.js 18
- Cache npm dependencies
- Install dependencies
- Run ESLint: `npm run lint`
- Fail on warnings (CI mode)

**Job 2: Test**
- Matrix strategy: Node 18, 20
- Checkout code
- Setup Node.js (matrix version)
- Cache npm dependencies
- Install dependencies
- Run tests with coverage: `npm test -- --coverage`
- Enforce coverage threshold: 90%
- Upload coverage report as artifact
- Optional: Upload to Codecov/Coveralls

**Job 3: Build**
- Checkout code
- Setup Node.js 18
- Cache npm dependencies
- Install dependencies
- Build TypeScript: `npm run build`
- Verify dist/ output exists
- Check for compilation errors
- Upload build artifacts

**Job 4: Security Audit**
- Checkout code
- Setup Node.js 18
- Run npm audit: `npm audit --audit-level=high`
- Fail on high/critical vulnerabilities
- Generate SARIF report
- Upload to GitHub Security tab

**Job 5: Docker Build**
- Depends on: lint, test, build
- Checkout code
- Setup Docker Buildx (for caching)
- Build Docker image
- Tag with commit SHA: `phishing-agent:${{ github.sha }}`
- Tag with branch: `phishing-agent:main`
- Optional: Push to GitHub Container Registry (ghcr.io)
- Verify image size (<100MB)

**Optimizations:**
- Dependency caching (npm, TypeScript)
- Parallel job execution
- Docker layer caching
- Skip jobs on documentation-only changes

**Status Badges:**
Add to README.md:
- Build status
- Test coverage
- Security audit

#### 2.2 GitHub Actions Deploy Workflow

**File:** `.github/workflows/deploy.yml`

**Triggers:**
- Manual workflow dispatch (with environment selection)
- Git tags matching `v*.*.*` (semantic versioning)
- Push to `production` branch (optional)

**Inputs:**
- Environment: staging | production
- Version tag (auto-generated from git tag or manual)

**Jobs:**

**Job 1: Build & Push to ACR**
- Checkout code
- Login to Azure CLI using service principal
- Login to Azure Container Registry
- Build Docker image with version tags
- Push to ACR with tags:
  - `{ACR_NAME}.azurecr.io/phishing-agent:latest`
  - `{ACR_NAME}.azurecr.io/phishing-agent:v{version}`
  - `{ACR_NAME}.azurecr.io/phishing-agent:{commit-sha}`

**Job 2: Deploy to Azure Container Apps**
- Depends on: build-and-push
- Environment: staging (auto) or production (manual approval)
- Login to Azure
- Update container app:
  ```bash
  az containerapp update \
    --name phishing-agent-{env} \
    --resource-group rg-phishing-agent-{env} \
    --image {ACR_NAME}.azurecr.io/phishing-agent:v{version} \
    --set-env-vars from GitHub Secrets
  ```
- Wait for deployment to complete
- Verify health check: `curl https://{app-url}/health`
- Run smoke tests: `curl https://{app-url}/ready`
- Rollback on failure: Revert to previous revision

**Job 3: Post-Deployment**
- Create GitHub release (on git tag)
- Update deployment status badge
- Send notification (Slack/Teams/Email)
- Log deployment to audit trail

**Environments:**
- **Staging**: Auto-deploy on git tags, no approval
- **Production**: Requires manual approval from security team

**Required GitHub Secrets:**
- `AZURE_CREDENTIALS` - Service principal JSON
- `AZURE_REGISTRY_URL` - ACR login server (e.g., myacr.azurecr.io)
- `AZURE_REGISTRY_USERNAME` - ACR username
- `AZURE_REGISTRY_PASSWORD` - ACR password
- `AZURE_SUBSCRIPTION_ID` - Azure subscription ID
- `AZURE_TENANT_ID` - Azure AD tenant ID
- `AZURE_CLIENT_ID` - App registration client ID
- `AZURE_CLIENT_SECRET` - App registration client secret (optional with Managed Identity)
- `PHISHING_MAILBOX_ADDRESS` - Monitored mailbox
- `VIRUSTOTAL_API_KEY` (optional)
- `ABUSEIPDB_API_KEY` (optional)
- `URLSCAN_API_KEY` (optional)

**Authentication Options:**

| Environment | Auth Method | Secrets Required |
|-------------|-------------|------------------|
| Production (Azure) | Managed Identity | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` only |
| Local Development | Client Secret | All Azure secrets including `AZURE_CLIENT_SECRET` |
| CI/CD Pipeline | Service Principal | `AZURE_CREDENTIALS` JSON |

**Managed Identity Benefits:**
- No secrets to rotate or manage
- Automatic credential handling by Azure
- Reduced attack surface (no secrets in environment)
- Automatic token refresh

---

### Phase 3: Azure Deployment Automation (Est: 45 min)

**Objective:** Automate Azure infrastructure setup and deployments

#### 3.1 Azure Setup Script

**File:** `deploy/azure-setup.sh`

**Purpose:** One-time infrastructure provisioning

**Actions:**
1. Create resource group: `rg-phishing-agent-{env}`
2. Create Azure Container Registry: `{prefix}phishingagent`
3. Create Log Analytics workspace: `law-phishing-agent-{env}`
4. Create Container Apps environment: `cae-phishing-agent-{env}`
5. Create Azure Key Vault: `kv-phishing-agent-{env}`
6. Store secrets in Key Vault:
   - Azure AD credentials
   - API keys
   - Mailbox configuration
7. Assign Managed Identity to Container App
8. Grant Key Vault access to Managed Identity
9. Configure Container App:
   - Min/max replicas (1/5)
   - CPU: 0.5 cores
   - Memory: 1GB
   - Ingress: HTTPS only, port 3000
   - Environment variables from Key Vault
10. Output deployment URLs and connection strings

**Usage:**
```bash
./deploy/azure-setup.sh \
  --environment production \
  --location eastus \
  --subscription "Your Subscription Name"
```

**Prerequisites:**
- Azure CLI installed and logged in
- Contributor role on subscription
- Azure AD permissions to create app registrations

#### 3.2 Azure Deploy Script

**File:** `deploy/azure-deploy.sh`

**Purpose:** Repeatable deployment script (local or CI/CD)

**Actions:**
1. Validate parameters (image tag, environment)
2. Build Docker image (if local)
3. Push to Azure Container Registry
4. Update Container App with new image
5. Apply environment variable updates
6. Wait for deployment (with timeout)
7. Verify health checks
8. Run smoke tests
9. Output deployment status

**Usage:**
```bash
# Deploy specific version
./deploy/azure-deploy.sh \
  --environment staging \
  --version v0.3.0

# Deploy latest
./deploy/azure-deploy.sh \
  --environment production \
  --version latest \
  --approve
```

**Rollback:**
```bash
# Rollback to previous revision
./deploy/azure-deploy.sh \
  --environment production \
  --rollback
```

#### 3.3 Azure Environment Configuration

**File:** `deploy/.env.example.azure`

**Purpose:** Template for Azure-specific environment variables

**Configuration:**
- Managed Identity integration (recommended)
- Azure Key Vault references (e.g., `@Microsoft.KeyVault(...)`)
- Application Insights connection string
- Azure Monitor workspace ID
- Custom domain configuration
- Auto-scaling rules
- Network isolation settings

---

### Phase 4: Documentation (Est: 30 min)

**Objective:** Comprehensive deployment documentation

#### 4.1 Create DEPLOYMENT.md

**File:** `DEPLOYMENT.md`

**Sections:**

1. **Prerequisites**
   - Docker Desktop installed
   - Azure CLI installed
   - GitHub account with Actions enabled
   - Azure subscription with permissions

2. **Local Development with Docker**
   - Build image: `docker build -t phishing-agent .`
   - Run locally: `docker run --env-file .env -p 3000:3000 phishing-agent`
   - Use docker-compose: `docker-compose up -d`
   - View logs: `docker-compose logs -f`
   - Stop: `docker-compose down`

3. **CI/CD Pipeline**
   - How CI workflow works (triggers, jobs)
   - How to configure GitHub secrets
   - How to trigger manual deployments
   - How to view build logs and artifacts
   - Troubleshooting CI failures

4. **Azure Deployment**
   - One-time setup with `azure-setup.sh`
   - Deploying with `azure-deploy.sh`
   - Deploying via GitHub Actions
   - Managing secrets in Key Vault
   - Viewing logs in Azure Portal
   - Scaling container instances
   - Custom domain setup

5. **Environment Variables Reference**
   - Complete list of all variables
   - Required vs optional
   - Default values
   - Example values
   - Security considerations

6. **Monitoring & Observability**
   - Health check endpoints
   - Log aggregation (Azure Monitor)
   - Metrics and dashboards
   - Alerting setup
   - Tracing requests

7. **Troubleshooting**
   - Container won't start
   - Health checks failing
   - Authentication errors
   - Network connectivity issues
   - Performance problems

8. **Rollback Procedures**
   - Rolling back via Azure Portal
   - Rolling back via CLI script
   - Rolling back via GitHub Actions
   - Verifying rollback success

#### 4.2 Update README.md

**Additions:**
- Docker badges (build status, image size, security scan)
- Quick Docker commands section
- Link to DEPLOYMENT.md for detailed instructions
- Update "Quick Start" with Docker option
- Add production deployment section

**Example Quick Start with Docker:**
```bash
# Using Docker
docker run --env-file .env -p 3000:3000 ghcr.io/afoxnyc3/phishing-agent:latest

# Using docker-compose
docker-compose up -d
```

#### 4.3 Update ARCHITECTURE.md

**Additions:**
- Deployment architecture diagram (ASCII or link to image)
- Container specifications (CPU, memory, storage)
- Azure resource topology:
  - Container Apps environment
  - Azure Container Registry
  - Log Analytics workspace
  - Key Vault
  - Managed Identity
  - Virtual Network (if applicable)
- Network configuration:
  - Ingress (HTTPS, port 3000)
  - Egress (Microsoft Graph API, threat intel APIs)
  - DNS and custom domains
- Scaling strategies:
  - Horizontal scaling (replicas)
  - Auto-scaling rules (HTTP traffic, CPU, memory)
  - Resource limits

---

## File Structure After Implementation

```
phishing-agent/
├── .github/
│   └── workflows/
│       ├── ci.yml              # NEW: CI pipeline
│       └── deploy.yml          # NEW: Deployment pipeline
├── deploy/                      # NEW: Deployment scripts directory
│   ├── azure-setup.sh          # NEW: One-time Azure setup
│   ├── azure-deploy.sh         # NEW: Deployment script
│   └── .env.example.azure      # NEW: Azure environment template
├── src/                         # (existing)
├── dist/                        # (existing build output)
├── .dockerignore               # NEW: Docker ignore file
├── Dockerfile                  # NEW: Multi-stage Docker build
├── docker-compose.yml          # NEW: Local development compose
├── DEPLOYMENT.md               # NEW: Deployment documentation
├── ARCHITECTURE.md             # (updated with deployment info)
├── README.md                   # (updated with Docker badges)
└── (other existing files)
```

---

## Testing & Validation Plan

### Local Testing (Phase 1)
1. Build Docker image locally
2. Run container with `.env` file
3. Verify health endpoint responds
4. Verify ready endpoint responds
5. Test mailbox monitoring (if credentials available)
6. Test graceful shutdown
7. Verify logs are properly formatted
8. Check image size (<100MB)

### CI Pipeline Testing (Phase 2)
1. Create test branch
2. Push changes to trigger CI
3. Verify lint job passes
4. Verify test job passes with coverage
5. Verify build job completes
6. Verify security audit passes
7. Verify Docker build succeeds
8. Check job execution time (<10 min total)

### Azure Deployment Testing (Phase 3)
1. Run `azure-setup.sh` in test subscription
2. Verify all Azure resources created
3. Deploy using `azure-deploy.sh`
4. Verify container app is running
5. Test health endpoint via public URL
6. Test ready endpoint via public URL
7. Send test email to monitored mailbox
8. Verify analysis and reply sent
9. Check logs in Azure Portal
10. Test scaling (manual trigger)

### End-to-End Testing
1. Make code change in feature branch
2. Open pull request
3. CI pipeline runs automatically
4. Merge to main after approval
5. Create git tag: `git tag v0.3.0`
6. Push tag: `git push origin v0.3.0`
7. Deploy workflow triggers automatically
8. Deployment to staging succeeds
9. Manual approval for production
10. Production deployment succeeds
11. Verify production mailbox monitoring

---

## Success Criteria

### Performance
- [ ] Docker image builds in <5 minutes
- [ ] Docker image size <100MB (target: 60-80MB)
- [ ] CI pipeline completes in <10 minutes
- [ ] Azure deployment completes in <5 minutes
- [ ] Health checks pass within 30 seconds of container start

### Quality
- [ ] All tests pass in CI
- [ ] Test coverage maintained at 90%+
- [ ] No high/critical security vulnerabilities
- [ ] ESLint passes with zero warnings
- [ ] Container starts successfully on first attempt

### Reliability
- [ ] Graceful shutdown works (SIGTERM handling)
- [ ] Health checks accurately reflect service status
- [ ] Container restarts automatically on failure
- [ ] Logs are structured and searchable
- [ ] Rollback works within 2 minutes

### Security
- [ ] Non-root user in container
- [ ] No secrets in Docker image layers
- [ ] Secrets stored in Azure Key Vault
- [ ] Managed Identity used where possible
- [ ] HTTPS-only ingress configured

### Documentation
- [ ] All deployment steps documented
- [ ] Troubleshooting guide complete
- [ ] Environment variables documented
- [ ] Architecture diagrams updated
- [ ] README badges working

---

## Risk Assessment

### Low Risk
- Docker containerization (isolated from existing code)
- CI pipeline setup (doesn't affect production)
- Documentation updates

### Medium Risk
- Azure deployment scripts (requires proper testing)
- GitHub secrets configuration (sensitive data)
- Container registry permissions

### Mitigation Strategies
1. Test all scripts in non-production environment first
2. Use separate Azure subscriptions for dev/staging/prod
3. Document all GitHub secrets with examples
4. Implement rollback procedures before first production deploy
5. Use staging environment to validate changes
6. Keep manual deployment option available

---

## Timeline & Milestones

### Week 1: Docker (Phase 1)
**Day 1-2:**
- Create Dockerfile, .dockerignore, docker-compose.yml
- Test local builds
- Optimize image size
- Document Docker usage

**Deliverable:** Working Docker container running locally

### Week 1: CI/CD (Phase 2)
**Day 3-4:**
- Create CI workflow (lint, test, build)
- Create deploy workflow skeleton
- Configure GitHub secrets documentation
- Test CI pipeline

**Deliverable:** Automated CI pipeline running on PRs

### Week 2: Azure (Phase 3)
**Day 5-6:**
- Create Azure setup script
- Create Azure deploy script
- Test in Azure test subscription
- Configure production environment

**Deliverable:** Automated deployment to Azure

### Week 2: Documentation (Phase 4)
**Day 7:**
- Write DEPLOYMENT.md
- Update README.md and ARCHITECTURE.md
- Create troubleshooting guide
- Final testing and validation

**Deliverable:** Complete deployment documentation

---

## Next Steps After Approval

1. **Immediate:** Create Dockerfile and test local build
2. **Day 1:** Complete Phase 1 (Docker containerization)
3. **Day 2:** Begin Phase 2 (CI pipeline)
4. **Day 3:** Complete Phase 2 and begin Phase 3
5. **Day 4:** Complete Phase 3 (Azure deployment)
6. **Day 5:** Complete Phase 4 (Documentation)
7. **Day 6:** End-to-end testing
8. **Day 7:** Production deployment

---

## Questions for Stakeholders

Before proceeding, please confirm:

1. **Azure Subscription:**
   - Do we have an Azure subscription ready?
   - What subscription should be used for prod vs staging?
   - Do we have necessary permissions?

2. **Container Registry:**
   - Use Azure Container Registry or GitHub Container Registry?
   - Naming convention for registry/images?

3. **Deployment Approval:**
   - Who should approve production deployments?
   - What's the approval process?

4. **Monitoring:**
   - Should we integrate Application Insights?
   - Any existing monitoring infrastructure to integrate with?

5. **Networking:**
   - Public internet access or VNet integration?
   - Custom domain requirements?
   - SSL certificate management?

6. **Costs:**
   - Budget for Azure resources?
   - Expected traffic/scaling requirements?

---

## Appendix: Resource Estimates

### Azure Monthly Costs (Estimated)

**Staging Environment:**
- Container App (1 replica, 0.5 CPU, 1GB RAM): ~$30/month
- Azure Container Registry (Basic): ~$5/month
- Log Analytics (5GB/month): ~$10/month
- **Total:** ~$45/month

**Production Environment:**
- Container App (2-5 replicas, 0.5 CPU, 1GB RAM): ~$60-150/month
- Azure Container Registry (Standard, shared): ~$20/month
- Log Analytics (20GB/month): ~$40/month
- Key Vault: ~$1/month
- **Total:** ~$120-210/month

**Notes:**
- Costs vary by region and actual usage
- Threat intel API costs not included (external services)
- Microsoft Graph API included in M365 license

### Development Time Estimates

- **Dockerfile creation:** 1-2 hours
- **CI pipeline setup:** 2-3 hours
- **Deploy pipeline setup:** 2-3 hours
- **Azure scripts:** 2-3 hours
- **Documentation:** 2-3 hours
- **Testing & validation:** 2-4 hours
- **Total:** 11-18 hours

With focused work: **2-3 days of implementation**

---

**Document Version:** 1.0
**Last Updated:** 2025-10-19
**Next Review:** After Phase 1 completion
