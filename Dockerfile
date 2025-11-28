# Phishing Agent - Multi-stage Docker Build
# Stage 1: Builder - Compile TypeScript
# Stage 2: Production - Minimal runtime image

# Build argument for Node version (20+ required for Azure SDK)
ARG NODE_VERSION=20

# ============================================
# Stage 1: Builder
# ============================================
FROM node:${NODE_VERSION}-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies (including devDependencies for build)
# --ignore-scripts skips husky prepare script which fails in Docker
RUN npm ci --no-audit --no-fund --ignore-scripts

# Copy TypeScript configuration and source code
COPY tsconfig.json ./
COPY src/ ./src/

# Build TypeScript to JavaScript
RUN npm run build

# Verify build output exists
RUN ls -la dist/

# ============================================
# Stage 2: Production
# ============================================
FROM node:${NODE_VERSION}-alpine

# OCI labels for image metadata
LABEL org.opencontainers.image.title="phishing-agent"
LABEL org.opencontainers.image.description="Email-triggered phishing analysis agent with automated risk assessment"
LABEL org.opencontainers.image.version="0.2.0"
LABEL org.opencontainers.image.source="https://github.com/afoxnyc3/phishing-agent"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Security Team"

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ONLY production dependencies
# --ignore-scripts skips husky prepare script which fails in Docker
RUN npm ci --omit=dev --no-audit --no-fund --ignore-scripts && \
    npm cache clean --force

# Copy compiled application from builder stage
COPY --from=builder --chown=node:node /app/dist ./dist

# Switch to non-root user for security
USER node

# Expose application port
EXPOSE 3000

# Health check using Node's built-in http module (no curl dependency)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1))"

# Start application (direct node execution for proper signal handling)
CMD ["node", "dist/index.js"]
