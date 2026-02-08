# RFC-0001: Azure Container Apps Deployment

## Status

Accepted

## Context

The phishing analysis agent needs a production deployment platform. The agent is a stateless HTTP service that:

- Processes emails independently (no shared state between requests)
- Requires integration with Azure services (Graph API, Key Vault)
- Has variable load (bursty email forwarding patterns)
- Needs health checks, graceful shutdown, and zero-downtime deploys

Options considered:

1. **Azure Container Apps** — serverless containers with auto-scaling
2. **Azure Kubernetes Service (AKS)** — full Kubernetes cluster
3. **Azure App Service** — PaaS with container support
4. **Azure Functions** — serverless functions

## Decision

Deploy on **Azure Container Apps** with a multi-stage Docker build.

Key factors:

- **Serverless scaling**: Scale from 1-5 replicas based on HTTP traffic, scale to zero in dev
- **Minimal operations**: No cluster management, patching, or node provisioning
- **Azure integration**: Native support for Managed Identity, Key Vault references, and Container Registry
- **Cost**: ~$30-50/month staging, ~$120-210/month production (vs $200+/month for AKS)
- **Docker strategy**: Multi-stage build targeting 60-80MB image (Alpine, non-root user)

AKS was rejected as overkill for a single-service deployment. App Service lacks the scaling flexibility. Functions would require significant refactoring of the Express HTTP server.

## Consequences

**Positive:**

- Reduced DevOps burden — no cluster management
- Built-in health checks, graceful shutdown, and revision management
- Cost-effective for bursty workloads

**Negative:**

- Locked into Azure ecosystem (mitigated: Docker container is portable)
- Limited networking options compared to AKS
- Cold start latency when scaling from zero (mitigated: minimum 1 replica in production)

## References

- [DEPLOYMENT_PLAN.md](../../DEPLOYMENT_PLAN.md) — full deployment guide
- [Azure Container Apps documentation](https://learn.microsoft.com/en-us/azure/container-apps/)
