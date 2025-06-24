# =============================================================================
# AI Security Posture Management Platform - Hybrid Microservices Dockerfile
# =============================================================================
# This multi-stage Dockerfile supports the hybrid microservices architecture:
# - Node.js API Gateway (main application and frontend)
# - Python Microservices (AI scanner, data integrity, Wiz integration, compliance)
# 
# Usage:
# - For Node.js API Gateway: docker build -t ai-spm-gateway .
# - For Python AI Scanner: docker build --target ai-scanner -t ai-spm-ai-scanner .
# - For Python Data Integrity: docker build --target data-integrity -t ai-spm-data-integrity .
# - For Python Wiz Integration: docker build --target wiz-integration -t ai-spm-wiz-integration .
# - For Python Compliance Engine: docker build --target compliance-engine -t ai-spm-compliance .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build Node.js Frontend and Backend (API Gateway)
# -----------------------------------------------------------------------------
# This stage builds the React frontend and Node.js backend for the API Gateway
FROM node:18-alpine AS nodejs-builder
WORKDIR /app

# Set environment for build optimization
ENV NODE_ENV=production

# Install build dependencies and copy package files
# Using --legacy-peer-deps to handle React 18 compatibility
COPY package.json package-lock.json* ./
RUN npm ci --legacy-peer-deps --only=production && \
    npm ci --legacy-peer-deps && \
    npm cache clean --force

# Copy source code for building
# Excludes microservices directory via .dockerignore for optimization
COPY . .

# Build the application
# - Frontend (React) assets go to dist/public/
# - Backend (Express) bundle goes to dist/index.js
# - Shared schemas and types are included in the build
RUN npm run build

# Clean up development dependencies to reduce image size
RUN npm prune --production

# -----------------------------------------------------------------------------
# Stage 2: Production Node.js API Gateway
# -----------------------------------------------------------------------------
# Lightweight production image for the Node.js API Gateway service
FROM node:18-alpine AS nodejs-gateway

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Install production dependencies
COPY --from=nodejs-builder /app/package.json ./package.json
COPY --from=nodejs-builder /app/node_modules ./node_modules

# Copy built application
# Frontend static assets for serving
COPY --from=nodejs-builder /app/dist ./dist

# Set ownership to non-root user
RUN chown -R nextjs:nodejs /app
USER nextjs

# Expose the API Gateway port
EXPOSE 5000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

# Start the Node.js API Gateway
# Uses the built Express server with integrated frontend serving
CMD ["node", "dist/index.js"]

# -----------------------------------------------------------------------------
# Stage 3: Python Base for Microservices
# -----------------------------------------------------------------------------
# Shared base image for all Python microservices with common dependencies
FROM python:3.11-slim AS python-base

# Install system dependencies required for Python packages
# - build-essential: Required for compiling Python packages
# - libpq-dev: PostgreSQL client library for database connections
# - curl: For health checks and external API calls
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app

# Set working directory
WORKDIR /app

# Set Python environment variables
# - PYTHONUNBUFFERED: Ensures Python output is sent straight to terminal
# - PYTHONDONTWRITEBYTECODE: Prevents Python from writing pyc files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# -----------------------------------------------------------------------------
# Stage 4: AI Scanner Microservice
# -----------------------------------------------------------------------------
# Python service for AI/ML model security analysis and bias detection
FROM python-base AS ai-scanner

# Copy microservice-specific requirements
COPY microservices/ai-scanner/requirements.txt ./requirements.txt

# Install Python dependencies
# Using --no-cache-dir to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy AI Scanner service code
COPY microservices/ai-scanner/ ./

# Set ownership to non-root user
RUN chown -R app:app /app
USER app

# Expose AI Scanner port
EXPOSE 8001

# Health check specific to AI Scanner service
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Start the AI Scanner microservice
# Uses uvicorn ASGI server for high-performance async Python web service
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]

# -----------------------------------------------------------------------------
# Stage 5: Data Integrity Microservice
# -----------------------------------------------------------------------------
# Python service for data quality monitoring and anomaly detection
FROM python-base AS data-integrity

# Copy microservice-specific requirements
COPY microservices/data-integrity/requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Data Integrity service code
COPY microservices/data-integrity/ ./

# Set ownership to non-root user
RUN chown -R app:app /app
USER app

# Expose Data Integrity port
EXPOSE 8002

# Health check specific to Data Integrity service
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Start the Data Integrity microservice
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002", "--workers", "1"]

# -----------------------------------------------------------------------------
# Stage 6: Wiz Integration Microservice
# -----------------------------------------------------------------------------
# Python service for external security platform integration and data transformation
FROM python-base AS wiz-integration

# Copy microservice-specific requirements
COPY microservices/wiz-integration/requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Wiz Integration service code
COPY microservices/wiz-integration/ ./

# Set ownership to non-root user
RUN chown -R app:app /app
USER app

# Expose Wiz Integration port
EXPOSE 8003

# Health check specific to Wiz Integration service
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1

# Start the Wiz Integration microservice
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003", "--workers", "1"]

# -----------------------------------------------------------------------------
# Stage 7: Compliance Engine Microservice
# -----------------------------------------------------------------------------
# Python service for automated compliance assessment and policy evaluation
FROM python-base AS compliance-engine

# Copy microservice-specific requirements
COPY microservices/compliance-engine/requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Compliance Engine service code
COPY microservices/compliance-engine/ ./

# Set ownership to non-root user
RUN chown -R app:app /app
USER app

# Expose Compliance Engine port
EXPOSE 8004

# Health check specific to Compliance Engine service
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8004/health || exit 1

# Start the Compliance Engine microservice
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004", "--workers", "1"]

# =============================================================================
# Build Examples:
# =============================================================================
# 
# Build Node.js API Gateway (default):
# docker build -t ai-spm-gateway .
# 
# Build specific Python microservices:
# docker build --target ai-scanner -t ai-spm-ai-scanner .
# docker build --target data-integrity -t ai-spm-data-integrity .
# docker build --target wiz-integration -t ai-spm-wiz-integration .
# docker build --target compliance-engine -t ai-spm-compliance-engine .
# 
# Build all microservices:
# docker build --target ai-scanner -t ai-spm-ai-scanner . && \
# docker build --target data-integrity -t ai-spm-data-integrity . && \
# docker build --target wiz-integration -t ai-spm-wiz-integration . && \
# docker build --target compliance-engine -t ai-spm-compliance-engine .
# 
# Run with Docker Compose for full stack:
# docker-compose up --build
# =============================================================================
