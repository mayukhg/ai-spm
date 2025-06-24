# Docker Deployment Guide - AI Security Posture Management Platform

This guide provides comprehensive instructions for deploying the AI-SPM platform using the hybrid microservices architecture with Docker and Docker Compose.

## Architecture Overview

The platform uses a multi-stage Docker approach with separate containers for:

- **Node.js API Gateway**: Frontend (React) + Backend (Express) + Authentication
- **AI Scanner Service**: Python FastAPI service for model security analysis
- **Data Integrity Service**: Python FastAPI service for data quality monitoring
- **Wiz Integration Service**: Python FastAPI service for external platform integration
- **Compliance Engine**: Python FastAPI service for compliance assessment
- **PostgreSQL Database**: Centralized data storage

## Quick Start

### 1. Prerequisites

- Docker 20.10+ 
- Docker Compose 2.0+
- 8GB+ RAM recommended
- 10GB+ free disk space

### 2. Initial Setup

```bash
# Clone repository
git clone <repository-url>
cd ai-spm-platform

# Copy environment configuration
cp .env.example .env

# Edit environment variables
nano .env
```

### 3. Deploy Full Stack

```bash
# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up --build -d
```

### 4. Access Application

- **Frontend**: http://localhost:5000
- **API Gateway**: http://localhost:5000/api
- **AI Scanner**: http://localhost:8001
- **Data Integrity**: http://localhost:8002
- **Wiz Integration**: http://localhost:8003
- **Compliance Engine**: http://localhost:8004
- **Database**: postgresql://localhost:5432/ai_spm_db

## Deployment Options

### Option 1: Full Hybrid Architecture

Deploy all services including Python microservices:

```bash
docker-compose up --build
```

**Services Started:**
- database (PostgreSQL)
- api-gateway (Node.js)
- ai-scanner (Python)
- data-integrity (Python)
- wiz-integration (Python)
- compliance-engine (Python)

### Option 2: API Gateway Only

Deploy just the Node.js API Gateway without microservices:

```bash
docker-compose up --build database api-gateway
```

**Services Started:**
- database (PostgreSQL)
- api-gateway (Node.js)

### Option 3: Selective Microservices

Deploy specific microservices as needed:

```bash
# Deploy with AI Scanner and Data Integrity only
docker-compose up --build database api-gateway ai-scanner data-integrity

# Deploy with external integration services
docker-compose up --build database api-gateway wiz-integration compliance-engine
```

## Individual Service Builds

### Build Node.js API Gateway

```bash
# Build API Gateway container
docker build -t ai-spm-gateway .

# Run standalone (requires external database)
docker run -p 5000:5000 \
  -e DATABASE_URL="postgresql://user:pass@host:5432/db" \
  ai-spm-gateway
```

### Build Python Microservices

```bash
# Build AI Scanner
docker build --target ai-scanner -t ai-spm-ai-scanner .

# Build Data Integrity Service
docker build --target data-integrity -t ai-spm-data-integrity .

# Build Wiz Integration Service
docker build --target wiz-integration -t ai-spm-wiz-integration .

# Build Compliance Engine
docker build --target compliance-engine -t ai-spm-compliance-engine .
```

### Run Individual Microservices

```bash
# Run AI Scanner
docker run -p 8001:8001 \
  -e PGHOST=database \
  -e PGPASSWORD=password \
  ai-spm-ai-scanner

# Run with database connection
docker run -p 8002:8002 \
  --network ai-spm-network \
  -e PGHOST=database \
  -e PGPASSWORD=password \
  ai-spm-data-integrity
```

## Environment Configuration

### Development Environment

```bash
# .env for development
NODE_ENV=development
LOG_LEVEL=DEBUG
DB_PASSWORD=dev_password
AI_SCANNER_URL=http://localhost:8001
```

### Production Environment

```bash
# .env for production
NODE_ENV=production
LOG_LEVEL=INFO
DB_PASSWORD=secure_production_password
AI_SCANNER_URL=http://ai-scanner:8001
SESSION_SECRET=64_character_secure_random_string
```

### Docker Compose Environment

```bash
# .env for Docker Compose
NODE_ENV=production
AI_SCANNER_URL=http://ai-scanner:8001
DATA_INTEGRITY_URL=http://data-integrity:8002
WIZ_INTEGRATION_URL=http://wiz-integration:8003
COMPLIANCE_ENGINE_URL=http://compliance-engine:8004
```

## Scaling and Performance

### Horizontal Scaling

```bash
# Scale microservices
docker-compose up --scale ai-scanner=3 --scale data-integrity=2

# Scale API Gateway
docker-compose up --scale api-gateway=2
```

### Resource Allocation

```yaml
# docker-compose.override.yml
version: '3.8'
services:
  api-gateway:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
  
  ai-scanner:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
```

## Monitoring and Health Checks

### Service Health Status

```bash
# Check all service health
docker-compose ps

# Check specific service logs
docker-compose logs -f api-gateway
docker-compose logs -f ai-scanner

# Check service health endpoints
curl http://localhost:5000/api/health
curl http://localhost:8001/health
curl http://localhost:8002/health
```

### Database Health

```bash
# Connect to database
docker-compose exec database psql -U ai_spm_user -d ai_spm_db

# Check database status
docker-compose exec database pg_isready -U ai_spm_user
```

## Data Management

### Database Initialization

The database is automatically initialized with:
- Required PostgreSQL extensions
- Performance optimizations
- Security configurations
- Initial schema (if Drizzle migrations don't run)

### Data Persistence

```bash
# View persistent volumes
docker volume ls | grep ai-spm

# Backup database
docker-compose exec database pg_dump -U ai_spm_user ai_spm_db > backup.sql

# Restore database
docker-compose exec -T database psql -U ai_spm_user ai_spm_db < backup.sql
```

### Data Migration

```bash
# Run database migrations (if using Drizzle)
docker-compose exec api-gateway npm run db:push

# Reset database (destructive)
docker-compose down -v
docker volume prune
docker-compose up --build
```

## Security Considerations

### Container Security

- All containers run as non-root users
- Minimal base images (Alpine Linux for Node.js, Debian Slim for Python)
- Security scanning enabled in ECR repositories
- Health checks for all services

### Network Security

```bash
# Custom network isolation
docker network create ai-spm-secure-network

# Run with custom network
docker-compose -f docker-compose.yml -f docker-compose.secure.yml up
```

### Secrets Management

```bash
# Use Docker secrets for production
echo "production_password" | docker secret create db_password -
echo "production_session_key" | docker secret create session_secret -
```

## Troubleshooting

### Common Issues

**Container Won't Start:**
```bash
# Check container logs
docker-compose logs service-name

# Check resource usage
docker stats

# Rebuild specific service
docker-compose build --no-cache service-name
```

**Database Connection Issues:**
```bash
# Check database connectivity
docker-compose exec api-gateway ping database

# Verify database credentials
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "SELECT version();"
```

**Port Conflicts:**
```bash
# Check port usage
netstat -tulpn | grep :5000

# Use different ports
docker-compose -f docker-compose.yml -f docker-compose.ports.yml up
```

### Performance Issues

**High Memory Usage:**
```bash
# Monitor resource usage
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Limit container resources
docker-compose -f docker-compose.yml -f docker-compose.limits.yml up
```

**Slow Database Queries:**
```bash
# Check database performance
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "SELECT * FROM pg_stat_activity;"

# Analyze query performance
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "EXPLAIN ANALYZE SELECT * FROM ai_assets;"
```

## Production Deployment

### AWS ECS Deployment

1. **Build and Push Images:**
```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Build and push Node.js API Gateway
docker build -t ai-spm-gateway .
docker tag ai-spm-gateway:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-nodejs-gateway:latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-nodejs-gateway:latest

# Build and push Python microservices
docker build --target ai-scanner -t ai-spm-ai-scanner .
docker tag ai-spm-ai-scanner:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:ai-scanner-latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:ai-scanner-latest
```

2. **Deploy CloudFormation Stack:**
```bash
aws cloudformation deploy \
  --template-file cloudformation.yaml \
  --stack-name ai-spm-production \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    DBPassword=secure_production_password \
    NodeJSImageTag=latest \
    PythonImageTag=latest \
    EnableMicroservices=true
```

### Kubernetes Deployment

1. **Create Kubernetes Manifests:**
```bash
# Generate Kubernetes manifests from Docker Compose
kompose convert -f docker-compose.yml
```

2. **Deploy to Kubernetes:**
```bash
kubectl apply -f k8s/
kubectl get pods -n ai-spm
```

## Maintenance

### Regular Maintenance Tasks

```bash
# Update images
docker-compose pull
docker-compose up --build

# Clean up unused resources
docker system prune -a

# Update database statistics
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "ANALYZE;"
```

### Backup Strategy

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec database pg_dump -U ai_spm_user ai_spm_db | gzip > "backup_${DATE}.sql.gz"
aws s3 cp "backup_${DATE}.sql.gz" s3://ai-spm-backups/
```

### Log Management

```bash
# Rotate logs
docker-compose exec api-gateway logrotate /etc/logrotate.conf

# Ship logs to external system
docker-compose -f docker-compose.yml -f docker-compose.logging.yml up
```

## Support and Monitoring

### Application Monitoring

- Health check endpoints on all services
- Structured logging in JSON format
- Metrics collection via Prometheus (if enabled)
- Distributed tracing support

### Alerting

Set up alerts for:
- Container health failures
- High resource usage
- Database connection issues
- External service integration failures

For additional support, refer to the main documentation and architecture diagrams.