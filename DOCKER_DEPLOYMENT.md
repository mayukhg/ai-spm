# Docker Deployment Guide - AI-SPM Service Mesh Architecture

This guide provides comprehensive instructions for deploying the AI Security Posture Management platform using the hybrid microservices architecture with Docker, Docker Compose, and service mesh integration.

## Architecture Overview

The platform uses a service mesh-ready multi-stage Docker approach with separate containers for:

- **Node.js API Gateway**: Frontend (React) + Backend (Express) + Authentication
- **AI Scanner Service**: Python FastAPI service for model security analysis
- **Data Integrity Service**: Python FastAPI service for data quality monitoring
- **Wiz Integration Service**: Python FastAPI service for external platform integration
- **Compliance Engine**: Python FastAPI service for compliance assessment
- **PostgreSQL Database**: Centralized data storage
- **Service Mesh Support**: Istio-ready containers with proper signal handling
- **Observability Stack**: Prometheus, Jaeger, Grafana for monitoring and tracing

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

### Option 1: Production Service Mesh (Recommended)

Deploy with Kubernetes and Istio service mesh for enterprise security:

```bash
# Prerequisites: Kubernetes cluster and Istio installed
# See SERVICE_MESH_GUIDE.md for complete instructions

# Deploy with service mesh
./deploy/service-mesh-deployment.sh deploy
```

**Features:**
- Automatic mTLS between all services
- Zero-trust security with authorization policies
- Distributed tracing and metrics collection
- Advanced traffic management and fault injection

### Option 2: Service Mesh Development Simulation

Deploy with Docker Compose and observability stack:

```bash
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml up --build
```

**Services Started:**
- database (PostgreSQL)
- api-gateway (Node.js) with mesh simulation
- ai-scanner (Python) with mesh simulation
- data-integrity (Python) with mesh simulation
- wiz-integration (Python) with mesh simulation
- compliance-engine (Python) with mesh simulation
- service-mesh-proxy (Nginx)
- jaeger (Distributed tracing)
- prometheus (Metrics collection)
- grafana (Dashboards)

### Option 3: Standard Docker Deployment

Deploy all services without service mesh:

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

### Option 4: API Gateway Only

Deploy just the Node.js API Gateway:

```bash
docker-compose up --build database api-gateway
```

### Option 5: Selective Microservices

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

### Service Mesh Development Environment

```bash
# .env for service mesh development simulation
NODE_ENV=development
LOG_LEVEL=DEBUG
DB_PASSWORD=dev_password
SERVICE_MESH_ENABLED=true
MESH_MODE=development
MTLS_MODE=PERMISSIVE
TRACE_SAMPLING=1.0
AI_SCANNER_URL=http://ai-scanner:8001
DATA_INTEGRITY_URL=http://data-integrity:8002
WIZ_INTEGRATION_URL=http://wiz-integration:8003
COMPLIANCE_ENGINE_URL=http://compliance-engine:8004
```

### Production Service Mesh Environment (Kubernetes)

```bash
# .env for Kubernetes with Istio
NODE_ENV=production
LOG_LEVEL=INFO
DB_PASSWORD=secure_production_password
SERVICE_MESH_ENABLED=true
MESH_MODE=production
MTLS_MODE=STRICT
AI_SCANNER_URL=http://ai-scanner.ai-spm.svc.cluster.local:8001
DATA_INTEGRITY_URL=http://data-integrity.ai-spm.svc.cluster.local:8002
WIZ_INTEGRATION_URL=http://wiz-integration.ai-spm.svc.cluster.local:8003
COMPLIANCE_ENGINE_URL=http://compliance-engine.ai-spm.svc.cluster.local:8004
SESSION_SECRET=64_character_secure_random_string
```

### Standard Docker Compose Environment

```bash
# .env for Docker Compose (without service mesh)
NODE_ENV=production
LOG_LEVEL=INFO
DB_PASSWORD=secure_production_password
SERVICE_MESH_ENABLED=false
AI_SCANNER_URL=http://ai-scanner:8001
DATA_INTEGRITY_URL=http://data-integrity:8002
WIZ_INTEGRATION_URL=http://wiz-integration:8003
COMPLIANCE_ENGINE_URL=http://compliance-engine:8004
SESSION_SECRET=64_character_secure_random_string
```

### Development Environment (Local)

```bash
# .env for local development
NODE_ENV=development
LOG_LEVEL=DEBUG
DB_PASSWORD=dev_password
SERVICE_MESH_ENABLED=false
AI_SCANNER_URL=http://localhost:8001
DATA_INTEGRITY_URL=http://localhost:8002
WIZ_INTEGRATION_URL=http://localhost:8003
COMPLIANCE_ENGINE_URL=http://localhost:8004
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
curl http://localhost:8003/health
curl http://localhost:8004/health
```

### Service Mesh Development Monitoring

```bash
# Check service mesh simulation
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml ps

# Check mesh proxy logs
docker-compose logs -f service-mesh-proxy

# Access observability dashboards
# Jaeger (distributed tracing): http://localhost:16686
# Prometheus (metrics): http://localhost:9090
# Grafana (dashboards): http://localhost:3000 (admin/admin)

# Test service mesh headers
curl -H "X-Service-Mesh: true" http://localhost:8080/api/health
```

### Database Health

```bash
# Connect to database
docker-compose exec database psql -U ai_spm_user -d ai_spm_db

# Check database status
docker-compose exec database pg_isready -U ai_spm_user
```

### Service Mesh Production Monitoring (Kubernetes)

```bash
# Check service mesh status
kubectl get pods -n ai-spm
kubectl get peerauthentication,authorizationpolicy -n ai-spm

# Check mTLS status
istioctl authn tls-check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Access observability dashboards
kubectl port-forward -n istio-system svc/kiali 20001:20001      # http://localhost:20001
kubectl port-forward -n istio-system svc/grafana 3000:3000     # http://localhost:3000
kubectl port-forward -n istio-system svc/jaeger 16686:16686    # http://localhost:16686
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

### Service Mesh Security

#### Zero Trust Architecture
- **Automatic mTLS**: All inter-service communication encrypted by default
- **Service Identity**: Each service has cryptographic identity with automatic certificate rotation
- **Authorization Policies**: Fine-grained access control between services
- **Network Segmentation**: Services isolated by default, explicit allow policies required

#### Security Verification
```bash
# Check mTLS status in production
istioctl authn tls-check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Verify authorization policies
istioctl auth check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Check certificate status
istioctl proxy-config secret $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm
```

### Container Security

- All containers run as non-root users (UID 1001)
- Minimal base images (Alpine Linux for Node.js, Debian Slim for Python)
- Security scanning enabled in ECR repositories
- Health checks for all services
- Read-only root filesystems where possible
- Dropped capabilities (ALL) for enhanced security

### Network Security

#### Service Mesh Development
```bash
# Test service mesh security headers
curl -I http://localhost:8080/api/health

# Verify mesh proxy configuration
docker-compose logs service-mesh-proxy
```

#### Kubernetes Network Security
```bash
# Apply network policies for additional isolation
kubectl apply -f k8s/network-policies.yaml

# Custom network isolation for Docker
docker network create ai-spm-secure-network

# Run with custom network
docker-compose -f docker-compose.yml -f docker-compose.secure.yml up
```

### Secrets Management

#### Kubernetes Secrets
```bash
# Create secrets using kubectl
kubectl create secret generic ai-spm-secrets \
  --from-literal=database-password='secure_password' \
  --from-literal=session-secret='64_char_secret' \
  --namespace=ai-spm

# For TLS certificates
kubectl create secret tls ai-spm-tls-cert \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem \
  --namespace=ai-spm
```

#### Docker Secrets
```bash
# Use Docker secrets for production
echo "production_password" | docker secret create db_password -
echo "production_session_key" | docker secret create session_secret -
```

#### External Secret Management
```bash
# Integration with external secret managers
kubectl apply -f k8s/external-secrets.yaml  # For AWS Secrets Manager, HashiCorp Vault, etc.
```

## Troubleshooting

### Service Mesh Issues

**Sidecar Injection Not Working:**
```bash
# Check namespace labels
kubectl get namespace ai-spm --show-labels

# Manually inject sidecar for testing
kubectl apply -f <(istioctl kube-inject -f k8s/deployments.yaml)

# Check Istio injection configuration
kubectl get configmap istio-sidecar-injector -n istio-system -o yaml
```

**mTLS Connection Issues:**
```bash
# Check TLS configuration
istioctl authn tls-check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Debug proxy configuration
istioctl proxy-config cluster $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Check certificate status
istioctl proxy-config secret $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm
```

**Authorization Policy Issues:**
```bash
# Check authorization status
istioctl auth check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Debug denied requests
kubectl logs -n ai-spm deployment/api-gateway -c istio-proxy | grep RBAC

# Test specific service communication
kubectl exec -n ai-spm deployment/api-gateway -- curl -v http://ai-scanner:8001/health
```

### Common Docker Issues

**Container Won't Start:**
```bash
# Check container logs
docker-compose logs service-name

# Check resource usage
docker stats

# Rebuild specific service
docker-compose build --no-cache service-name

# Check service mesh simulation
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml logs service-mesh-proxy
```

**Database Connection Issues:**
```bash
# Check database connectivity
docker-compose exec api-gateway ping database

# Verify database credentials
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "SELECT version();"

# Test database connection with service mesh headers
docker-compose exec api-gateway curl -H "X-Service-Mesh: true" http://database:5432
```

**Port Conflicts:**
```bash
# Check port usage
netstat -tulpn | grep :5000
netstat -tulpn | grep :8080  # Service mesh proxy
netstat -tulpn | grep :16686 # Jaeger
netstat -tulpn | grep :9090  # Prometheus

# Use different ports
docker-compose -f docker-compose.yml -f docker-compose.ports.yml up
```

**Service Mesh Development Issues:**
```bash
# Check mesh proxy status
docker-compose logs service-mesh-proxy

# Verify observability stack
curl http://localhost:9090/api/v1/targets  # Prometheus targets
curl http://localhost:16686/api/services   # Jaeger services

# Test mesh headers
curl -H "X-Service-Mesh: true" -I http://localhost:8080/api/health
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

### Service Mesh Deployment (Recommended)

1. **Deploy with Istio Service Mesh:**
```bash
# Install Istio (if not already installed)
curl -L https://istio.io/downloadIstio | sh -
export PATH=$PWD/istio-1.20.0/bin:$PATH

# Deploy complete service mesh architecture
chmod +x deploy/service-mesh-deployment.sh
./deploy/service-mesh-deployment.sh deploy

# Verify deployment
kubectl get pods -n ai-spm
istioctl proxy-status
```

**Service Mesh Features:**
- Automatic mTLS between all services
- Zero-trust security architecture
- Distributed tracing and metrics
- Advanced traffic management
- Circuit breaking and fault injection

2. **Access Application:**
```bash
# Get gateway external IP
GATEWAY_IP=$(kubectl get service istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "Application URL: http://$GATEWAY_IP/"

# Access observability dashboards
kubectl port-forward -n istio-system svc/kiali 20001:20001      # Service mesh topology
kubectl port-forward -n istio-system svc/grafana 3000:3000     # Metrics dashboards
kubectl port-forward -n istio-system svc/jaeger 16686:16686    # Distributed tracing
```

### AWS ECS Deployment (Service Mesh Ready)

1. **Build and Push Service Mesh Ready Images:**
```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Build and push Node.js API Gateway (service mesh ready)
docker build -t ai-spm-gateway .
docker tag ai-spm-gateway:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-nodejs-gateway:latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-nodejs-gateway:latest

# Build and push Python microservices (service mesh ready)
docker build --target ai-scanner -t ai-spm-ai-scanner .
docker build --target data-integrity -t ai-spm-data-integrity .
docker build --target wiz-integration -t ai-spm-wiz-integration .
docker build --target compliance-engine -t ai-spm-compliance-engine .

# Tag and push each microservice
docker tag ai-spm-ai-scanner:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:ai-scanner-latest
docker tag ai-spm-data-integrity:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:data-integrity-latest
docker tag ai-spm-wiz-integration:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:wiz-integration-latest
docker tag ai-spm-compliance-engine:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:compliance-engine-latest

docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:ai-scanner-latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:data-integrity-latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:wiz-integration-latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/ai-spm-python-microservices:compliance-engine-latest
```

2. **Deploy CloudFormation Stack with Service Mesh Support:**
```bash
aws cloudformation deploy \
  --template-file cloudformation.yaml \
  --stack-name ai-spm-production \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    DBPassword=secure_production_password \
    NodeJSImageTag=latest \
    PythonImageTag=latest \
    EnableMicroservices=true \
    ServiceMeshReady=true \
    KubernetesClusterName=ai-spm-eks-cluster
```

### Kubernetes Deployment (Manual)

1. **Create Kubernetes Resources:**
```bash
# Apply namespace with Istio injection
kubectl apply -f istio/namespace.yaml

# Create secrets
kubectl create secret generic ai-spm-secrets \
  --from-literal=database-password='your_secure_password' \
  --from-literal=session-secret='your_64_character_session_secret' \
  --namespace=ai-spm

# Deploy storage and configuration
kubectl apply -f k8s/storage.yaml
kubectl apply -f k8s/configmaps.yaml

# Deploy services and applications
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/deployments.yaml
```

2. **Configure Service Mesh:**
```bash
# Apply security policies
kubectl apply -f istio/peer-authentication.yaml
kubectl apply -f istio/authorization-policy.yaml

# Apply traffic management
kubectl apply -f istio/virtual-service.yaml
kubectl apply -f istio/destination-rules.yaml
kubectl apply -f istio/gateway.yaml

# Enable telemetry
kubectl apply -f istio/telemetry.yaml
```

## Maintenance

### Service Mesh Maintenance

#### Certificate Management
```bash
# Check certificate expiration
kubectl get secret -n ai-spm ai-spm-tls-cert -o yaml

# Rotate certificates (automatic in Istio)
istioctl proxy-config secret $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Force certificate rotation if needed
kubectl delete secret istio-ca-secret -n istio-system
kubectl rollout restart deployment/istiod -n istio-system
```

#### Service Mesh Updates
```bash
# Update Istio version
istioctl upgrade --set values.defaultRevision=1.20.1

# Update service mesh policies
kubectl apply -f istio/
kubectl rollout restart deployment -n ai-spm
```

### Regular Maintenance Tasks

#### Container Updates
```bash
# Update images
docker-compose pull
docker-compose up --build

# Update with service mesh simulation
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml pull
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml up --build

# Clean up unused resources
docker system prune -a
docker volume prune
```

#### Database Maintenance
```bash
# Update database statistics
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "ANALYZE;"

# Vacuum database
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "VACUUM ANALYZE;"

# Check database health
docker-compose exec database psql -U ai_spm_user -d ai_spm_db -c "SELECT * FROM pg_stat_activity;"
```

### Backup Strategy

#### Service Mesh Aware Backups
```bash
# Automated backup script with service mesh considerations
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
if kubectl get namespace ai-spm &> /dev/null; then
    # Kubernetes deployment
    kubectl exec -n ai-spm deployment/database -- pg_dump -U ai_spm_user ai_spm_db | gzip > "backup_${DATE}.sql.gz"
    
    # Backup service mesh configuration
    kubectl get peerauthentication,authorizationpolicy,virtualservice,destinationrule,gateway -n ai-spm -o yaml > "mesh_config_${DATE}.yaml"
else
    # Docker deployment
    docker-compose exec database pg_dump -U ai_spm_user ai_spm_db | gzip > "backup_${DATE}.sql.gz"
fi

# Upload to cloud storage
aws s3 cp "backup_${DATE}.sql.gz" s3://ai-spm-backups/
aws s3 cp "mesh_config_${DATE}.yaml" s3://ai-spm-backups/ 2>/dev/null || true
```

#### Configuration Backup
```bash
# Backup service mesh configuration
kubectl get peerauthentication,authorizationpolicy,virtualservice,destinationrule,gateway -n ai-spm -o yaml > service-mesh-backup.yaml

# Backup secrets (metadata only, not values)
kubectl get secrets -n ai-spm -o yaml | kubectl neat > secrets-structure.yaml
```

### Log Management

#### Service Mesh Logging
```bash
# Access service mesh access logs
kubectl logs -n ai-spm deployment/api-gateway -c istio-proxy

# Aggregate logs from all services
kubectl logs -n ai-spm -l tier=microservice -c istio-proxy --tail=100

# Ship logs to external system with service mesh context
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml -f docker-compose.logging.yml up
```

#### Observability Data Management
```bash
# Clean up old tracing data
curl -X DELETE "http://localhost:16686/api/traces?service=api-gateway&start=$(date -d '30 days ago' +%s)000000"

# Manage Prometheus data retention
docker-compose exec prometheus promtool query range \
  --start='2024-01-01T00:00:00Z' \
  --end='2024-12-31T23:59:59Z' \
  'up'

# Grafana dashboard backup
docker-compose exec grafana grafana-cli admin export-dashboard --path=/tmp/dashboards/
```

#### Log Rotation and Cleanup
```bash
# Rotate Docker logs
docker-compose exec api-gateway logrotate /etc/logrotate.conf

# Clean up old service mesh proxy logs
kubectl exec -n ai-spm deployment/api-gateway -c istio-proxy -- find /var/log -name "*.log" -mtime +7 -delete

# Configure centralized logging
kubectl apply -f k8s/logging-config.yaml
```

## Support and Monitoring

### Service Mesh Observability

#### Distributed Tracing
```bash
# Access Jaeger UI
kubectl port-forward -n istio-system svc/jaeger 16686:16686
# Open: http://localhost:16686

# For Docker development
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml up
# Open: http://localhost:16686
```

#### Service Mesh Topology
```bash
# Access Kiali UI
kubectl port-forward -n istio-system svc/kiali 20001:20001
# Open: http://localhost:20001

# View service mesh graph
curl http://localhost:20001/api/namespaces/ai-spm/graph
```

#### Metrics and Dashboards
```bash
# Access Grafana dashboards
kubectl port-forward -n istio-system svc/grafana 3000:3000
# Open: http://localhost:3000

# For Docker development
# Open: http://localhost:3000 (admin/admin)

# Prometheus metrics
kubectl port-forward -n istio-system svc/prometheus 9090:9090
# Open: http://localhost:9090
```

### Application Monitoring

#### Health Check Endpoints
- **API Gateway**: `http://localhost:5000/api/health`
- **AI Scanner**: `http://localhost:8001/health`
- **Data Integrity**: `http://localhost:8002/health`
- **Wiz Integration**: `http://localhost:8003/health`
- **Compliance Engine**: `http://localhost:8004/health`
- **Service Mesh Proxy**: `http://localhost:8080/health` (development)

#### Service Mesh Metrics
- mTLS connection success rates
- Authorization policy allow/deny rates
- Service-to-service latency
- Certificate rotation events
- Proxy resource utilization

#### Structured Logging
- JSON format logs from all services
- Service mesh access logs with mTLS context
- Distributed tracing correlation IDs
- Security event logging

### Alerting

#### Service Mesh Alerts
Set up alerts for:
- mTLS certificate expiration
- Authorization policy violations
- Service mesh control plane health
- Proxy sidecar failures
- Inter-service communication failures

#### Application Alerts
Set up alerts for:
- Container health failures
- High resource usage
- Database connection issues
- External service integration failures
- Service mesh policy violations

#### Monitoring Configuration
```bash
# Prometheus alerting rules
kubectl apply -f k8s/prometheus-rules.yaml

# Grafana alert notifications
kubectl apply -f k8s/grafana-notifications.yaml

# Service mesh specific alerts
kubectl apply -f istio/alerting-rules.yaml
```

### Documentation and Support

#### Service Mesh Documentation
- **SERVICE_MESH_GUIDE.md**: Comprehensive service mesh deployment guide
- **ARCHITECTURE_DIAGRAM.md**: Visual service mesh architecture
- **k8s/**: Complete Kubernetes manifests with service mesh integration
- **istio/**: Istio configuration files and policies

#### Additional Resources
- **README.md**: Updated with service mesh deployment options
- **ARCHITECTURE.md**: Service mesh architecture details
- **Docker Compose files**: Development simulation of service mesh
- **CloudFormation template**: Service mesh ready AWS infrastructure

#### Support Channels
- Service mesh configuration validation: `istioctl analyze`
- Proxy configuration debugging: `istioctl proxy-config`
- Security policy validation: `istioctl auth check`
- Performance profiling: Service mesh observability stack

For production service mesh deployments, refer to the SERVICE_MESH_GUIDE.md for comprehensive installation and management instructions.