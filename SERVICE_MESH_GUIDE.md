# AI-SPM Service Mesh Implementation Guide

This guide provides comprehensive instructions for deploying and managing the AI Security Posture Management platform with Istio service mesh.

## Overview

The AI-SPM platform implements a service mesh architecture using Istio to provide:

- **Automatic mTLS**: Zero-configuration mutual TLS encryption between all services
- **Authorization Policies**: Fine-grained access control and zero-trust security  
- **Traffic Management**: Advanced routing, load balancing, and fault injection
- **Observability**: Distributed tracing, metrics collection, and access logging

## Prerequisites

### Required Tools
- **Kubernetes 1.24+**: Container orchestration platform
- **Istio 1.20+**: Service mesh platform
- **kubectl**: Kubernetes command-line tool
- **istioctl**: Istio command-line tool
- **Helm 3.0+**: Package manager for Kubernetes (optional)

### Cluster Requirements
- Minimum 4 CPU cores and 8GB RAM
- LoadBalancer service support
- Persistent storage capabilities
- Network policies support (recommended)

## Installation

### Quick Start

```bash
# 1. Download and install Istio
curl -L https://istio.io/downloadIstio | sh -
export PATH=$PWD/istio-1.20.0/bin:$PATH

# 2. Deploy AI-SPM with service mesh
chmod +x deploy/service-mesh-deployment.sh
./deploy/service-mesh-deployment.sh deploy
```

### Manual Installation

#### Step 1: Install Istio

```bash
# Install Istio with production configuration
istioctl install --set values.defaultRevision=default \
  --set values.pilot.traceSampling=1.0 \
  --set values.global.meshID=ai-spm-mesh \
  --set values.global.network=ai-spm-network \
  --set values.global.proxy.privileged=false \
  --set values.telemetry.v2.prometheus.configOverride.disable_host_header_fallback=true \
  -y

# Verify installation
kubectl get pods -n istio-system
```

#### Step 2: Install Observability Addons

```bash
# Install Prometheus, Grafana, Jaeger, and Kiali
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/prometheus.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/grafana.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/jaeger.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/kiali.yaml
```

#### Step 3: Create AI-SPM Namespace

```bash
# Create namespace with Istio injection enabled
kubectl apply -f istio/namespace.yaml

# Verify Istio injection is enabled
kubectl get namespace ai-spm --show-labels
```

#### Step 4: Deploy Secrets and Configuration

```bash
# Create application secrets
kubectl create secret generic ai-spm-secrets \
  --from-literal=database-password='your_secure_password' \
  --from-literal=session-secret='your_64_character_session_secret' \
  --namespace=ai-spm

# Deploy configuration maps
kubectl apply -f k8s/configmaps.yaml
```

#### Step 5: Deploy Storage and Applications

```bash
# Deploy persistent storage
kubectl apply -f k8s/storage.yaml

# Deploy services and deployments
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/deployments.yaml
```

#### Step 6: Configure Service Mesh Security

```bash
# Apply strict mTLS policies
kubectl apply -f istio/peer-authentication.yaml

# Apply authorization policies
kubectl apply -f istio/authorization-policy.yaml
```

#### Step 7: Configure Traffic Management

```bash
# Apply virtual services for routing
kubectl apply -f istio/virtual-service.yaml

# Apply destination rules for load balancing
kubectl apply -f istio/destination-rules.yaml

# Apply gateways for external access
kubectl apply -f istio/gateway.yaml
```

#### Step 8: Enable Telemetry

```bash
# Apply telemetry configuration
kubectl apply -f istio/telemetry.yaml
```

## Configuration

### mTLS Configuration

The platform enforces strict mTLS by default:

```yaml
# Strict mTLS for all services
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: ai-spm-mtls-strict
  namespace: ai-spm
spec:
  mtls:
    mode: STRICT
```

### Authorization Policies

Services communicate through fine-grained authorization:

```yaml
# API Gateway to microservices
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: api-gateway-to-microservices
  namespace: ai-spm
spec:
  selector:
    matchLabels:
      tier: microservice
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/ai-spm/sa/api-gateway"]
    to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]
```

### Traffic Management

Intelligent routing and load balancing:

```yaml
# API Gateway virtual service
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: api-gateway-vs
  namespace: ai-spm
spec:
  hosts:
  - api-gateway
  http:
  - route:
    - destination:
        host: api-gateway
    timeout: 30s
    retries:
      attempts: 2
```

## Verification

### Check Service Mesh Status

```bash
# Verify all pods have Istio sidecars
kubectl get pods -n ai-spm -o wide

# Check mTLS status
istioctl authn tls-check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Verify authorization policies
istioctl auth check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm
```

### Test Service Connectivity

```bash
# Test internal service communication
kubectl exec -n ai-spm deployment/api-gateway -- curl -f http://ai-scanner:8001/health
kubectl exec -n ai-spm deployment/api-gateway -- curl -f http://data-integrity:8002/health
kubectl exec -n ai-spm deployment/api-gateway -- curl -f http://wiz-integration:8003/health
kubectl exec -n ai-spm deployment/api-gateway -- curl -f http://compliance-engine:8004/health
```

### Verify External Access

```bash
# Get gateway external IP
GATEWAY_IP=$(kubectl get service istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Test external access
curl -f http://$GATEWAY_IP/api/health
```

## Observability

### Access Dashboards

```bash
# Kiali (service mesh topology)
kubectl port-forward -n istio-system svc/kiali 20001:20001
# Access: http://localhost:20001

# Grafana (metrics dashboards)
kubectl port-forward -n istio-system svc/grafana 3000:3000
# Access: http://localhost:3000

# Jaeger (distributed tracing)
kubectl port-forward -n istio-system svc/jaeger 16686:16686
# Access: http://localhost:16686

# Prometheus (metrics)
kubectl port-forward -n istio-system svc/prometheus 9090:9090
# Access: http://localhost:9090
```

### Monitor Service Mesh

1. **Service Topology**: Use Kiali to visualize service dependencies and traffic flow
2. **Distributed Tracing**: Use Jaeger to trace requests across services
3. **Metrics**: Use Grafana dashboards to monitor performance and security metrics
4. **Access Logs**: Review detailed logs of all service communications

## Security Features

### Zero Trust Architecture

- **Service Identity**: Each service has unique cryptographic identity
- **Certificate Rotation**: Automatic certificate lifecycle management
- **Policy Enforcement**: Declarative security policies enforced at proxy level
- **Network Segmentation**: Services isolated by default, explicit allow policies required

### Monitoring Security

```bash
# Check certificate status
istioctl proxy-config secret $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# View security policies
kubectl get peerauthentication,authorizationpolicy -n ai-spm

# Monitor security events
kubectl logs -n istio-system deployment/istiod | grep -i security
```

## Troubleshooting

### Common Issues

#### Sidecar Injection Not Working
```bash
# Check namespace labels
kubectl get namespace ai-spm --show-labels

# Manually inject sidecar
kubectl apply -f <(istioctl kube-inject -f k8s/deployments.yaml)
```

#### mTLS Issues
```bash
# Check TLS configuration
istioctl authn tls-check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Debug proxy configuration
istioctl proxy-config cluster $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm
```

#### Authorization Policy Issues
```bash
# Check authorization status
istioctl auth check $(kubectl get pods -n ai-spm -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').ai-spm

# Debug denied requests
kubectl logs -n ai-spm deployment/api-gateway -c istio-proxy | grep RBAC
```

### Performance Tuning

#### Optimize Proxy Resources
```yaml
annotations:
  sidecar.istio.io/proxyCPU: "100m"
  sidecar.istio.io/proxyMemory: "128Mi"
```

#### Configure Connection Pools
```yaml
spec:
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 10
      http:
        http1MaxPendingRequests: 5
        maxRequestsPerConnection: 2
```

## Development Workflow

### Service Mesh Development

```bash
# Use development service mesh simulation
docker-compose -f docker-compose.yml -f docker-compose.service-mesh.yml up --build

# Access development observability
# Jaeger: http://localhost:16686
# Grafana: http://localhost:3000
# Prometheus: http://localhost:9090
```

### Testing Service Mesh Policies

```bash
# Test authorization policies
kubectl create -f test-pods.yaml
kubectl exec test-pod -- curl http://api-gateway:5000/api/health

# Test mTLS enforcement
kubectl exec test-pod -- openssl s_client -connect api-gateway:5000 -verify_return_error
```

## Production Considerations

### High Availability

- Deploy multiple Istio control plane instances
- Configure cross-region service mesh federation
- Implement disaster recovery procedures

### Security Hardening

- Enable audit logging for all security events
- Implement external certificate authority integration
- Configure network policies for additional isolation
- Regular security scanning of service mesh components

### Performance Monitoring

- Set up comprehensive alerting for service mesh metrics
- Monitor certificate expiration and rotation
- Track service mesh resource utilization
- Implement SLA monitoring for critical service paths

## Advanced Features

### Multi-Cluster Service Mesh

For multi-cluster deployments:

```bash
# Install on primary cluster
istioctl install --set values.pilot.env.ISTIOD_CUSTOM_CA_CERT_NAME=cacerts

# Install on remote cluster
istioctl install --set values.istiodRemote.enabled=true \
  --set values.pilot.env.EXTERNAL_ISTIOD=true
```

### Service Mesh Federation

Connect multiple AI-SPM instances across regions:

```bash
# Configure cross-cluster service discovery
istioctl create-remote-secret --name=cluster2 | kubectl apply -f -
```

This comprehensive guide covers all aspects of deploying and managing the AI-SPM platform with Istio service mesh, providing enterprise-grade security, observability, and traffic management capabilities.