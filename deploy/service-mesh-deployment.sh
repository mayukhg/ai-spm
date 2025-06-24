#!/bin/bash
# =============================================================================
# AI-SPM Service Mesh Deployment Script
# =============================================================================
# This script deploys the AI Security Posture Management platform with Istio
# service mesh, including mTLS enforcement and comprehensive observability.
# =============================================================================

set -euo pipefail

# Configuration
NAMESPACE="ai-spm"
CLUSTER_NAME="ai-spm-cluster"
REGION="us-east-1"
ISTIO_VERSION="1.20.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
    fi
    
    # Check istioctl
    if ! command -v istioctl &> /dev/null; then
        log_error "istioctl is not installed or not in PATH"
    fi
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
    fi
    
    log_success "Prerequisites check passed"
}

# Install Istio
install_istio() {
    log_info "Installing Istio service mesh..."
    
    # Check if Istio is already installed
    if kubectl get namespace istio-system &> /dev/null; then
        log_warning "Istio appears to be already installed, skipping installation"
        return 0
    fi
    
    # Install Istio with production configuration
    istioctl install --set values.defaultRevision=default \
        --set values.pilot.traceSampling=1.0 \
        --set values.global.meshID=ai-spm-mesh \
        --set values.global.network=ai-spm-network \
        --set values.global.proxy.privileged=false \
        --set values.global.proxy.enableCoreDump=false \
        --set values.telemetry.v2.prometheus.configOverride.disable_host_header_fallback=true \
        --set values.telemetry.v2.prometheus.configOverride.metric_relabeling_configs[0].source_labels='[__name__]' \
        --set values.telemetry.v2.prometheus.configOverride.metric_relabeling_configs[0].regex='istio_.*' \
        --set values.telemetry.v2.prometheus.configOverride.metric_relabeling_configs[0].action=keep \
        -y
    
    # Wait for Istio to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/istiod -n istio-system
    
    log_success "Istio installed successfully"
}

# Install Istio addons for observability
install_istio_addons() {
    log_info "Installing Istio observability addons..."
    
    # Install Prometheus
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION}/samples/addons/prometheus.yaml
    
    # Install Grafana
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION}/samples/addons/grafana.yaml
    
    # Install Jaeger
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION}/samples/addons/jaeger.yaml
    
    # Install Kiali
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION}/samples/addons/kiali.yaml
    
    # Wait for addons to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/prometheus -n istio-system
    kubectl wait --for=condition=available --timeout=300s deployment/grafana -n istio-system
    kubectl wait --for=condition=available --timeout=300s deployment/jaeger -n istio-system
    kubectl wait --for=condition=available --timeout=300s deployment/kiali -n istio-system
    
    log_success "Istio addons installed successfully"
}

# Create namespace and apply Istio configuration
setup_namespace() {
    log_info "Setting up AI-SPM namespace..."
    
    # Create namespace with Istio injection enabled
    kubectl apply -f istio/namespace.yaml
    
    # Wait for namespace to be ready
    kubectl wait --for=condition=Active --timeout=60s namespace/${NAMESPACE}
    
    log_success "Namespace created and configured"
}

# Deploy secrets (template - requires manual configuration)
deploy_secrets() {
    log_info "Deploying secrets..."
    
    # Check if secrets already exist
    if kubectl get secret ai-spm-secrets -n ${NAMESPACE} &> /dev/null; then
        log_warning "Secrets already exist, skipping deployment"
        return 0
    fi
    
    # Create secrets from environment variables or prompt user
    if [[ -z "${DB_PASSWORD:-}" ]]; then
        log_warning "DB_PASSWORD not set in environment"
        read -s -p "Enter database password: " DB_PASSWORD
        echo
    fi
    
    if [[ -z "${SESSION_SECRET:-}" ]]; then
        log_warning "SESSION_SECRET not set in environment"
        read -s -p "Enter session secret (64 characters): " SESSION_SECRET
        echo
    fi
    
    # Create the secret
    kubectl create secret generic ai-spm-secrets \
        --from-literal=database-password="${DB_PASSWORD}" \
        --from-literal=session-secret="${SESSION_SECRET}" \
        --from-literal=database-url="postgresql://ai_spm_user:${DB_PASSWORD}@database.ai-spm.svc.cluster.local:5432/ai_spm_db" \
        --namespace=${NAMESPACE}
    
    log_success "Secrets deployed successfully"
}

# Deploy storage resources
deploy_storage() {
    log_info "Deploying storage resources..."
    
    kubectl apply -f k8s/storage.yaml
    
    # Wait for PVCs to be bound
    kubectl wait --for=condition=Bound --timeout=300s pvc/postgres-pvc -n ${NAMESPACE}
    
    log_success "Storage resources deployed successfully"
}

# Deploy configuration maps
deploy_configmaps() {
    log_info "Deploying configuration maps..."
    
    kubectl apply -f k8s/configmaps.yaml
    
    log_success "Configuration maps deployed successfully"
}

# Deploy services and deployments
deploy_applications() {
    log_info "Deploying AI-SPM applications..."
    
    # Deploy services first
    kubectl apply -f k8s/services.yaml
    
    # Deploy applications
    kubectl apply -f k8s/deployments.yaml
    
    # Wait for deployments to be ready
    log_info "Waiting for deployments to be ready..."
    kubectl wait --for=condition=available --timeout=600s deployment/database -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=600s deployment/api-gateway -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=600s deployment/ai-scanner -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=600s deployment/data-integrity -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=600s deployment/wiz-integration -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=600s deployment/compliance-engine -n ${NAMESPACE}
    
    log_success "Applications deployed successfully"
}

# Deploy Istio security policies
deploy_security_policies() {
    log_info "Deploying Istio security policies..."
    
    # Apply PeerAuthentication for mTLS
    kubectl apply -f istio/peer-authentication.yaml
    
    # Apply AuthorizationPolicy for access control
    kubectl apply -f istio/authorization-policy.yaml
    
    log_success "Security policies deployed successfully"
}

# Deploy Istio traffic management
deploy_traffic_management() {
    log_info "Deploying Istio traffic management..."
    
    # Apply VirtualServices
    kubectl apply -f istio/virtual-service.yaml
    
    # Apply DestinationRules
    kubectl apply -f istio/destination-rules.yaml
    
    # Apply Gateways
    kubectl apply -f istio/gateway.yaml
    
    log_success "Traffic management deployed successfully"
}

# Deploy telemetry configuration
deploy_telemetry() {
    log_info "Deploying telemetry configuration..."
    
    kubectl apply -f istio/telemetry.yaml
    
    log_success "Telemetry configuration deployed successfully"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pod status
    log_info "Pod status:"
    kubectl get pods -n ${NAMESPACE}
    
    # Check service status
    log_info "Service status:"
    kubectl get services -n ${NAMESPACE}
    
    # Check Istio configuration
    log_info "Istio configuration:"
    kubectl get peerauthentication,authorizationpolicy,virtualservice,destinationrule,gateway -n ${NAMESPACE}
    
    # Check mTLS status
    log_info "Checking mTLS status..."
    istioctl authn tls-check $(kubectl get pods -n ${NAMESPACE} -l app=api-gateway -o jsonpath='{.items[0].metadata.name}').${NAMESPACE}
    
    # Test connectivity
    log_info "Testing service connectivity..."
    kubectl exec -n ${NAMESPACE} deployment/api-gateway -- curl -f http://ai-scanner:8001/health || log_warning "AI Scanner health check failed"
    kubectl exec -n ${NAMESPACE} deployment/api-gateway -- curl -f http://data-integrity:8002/health || log_warning "Data Integrity health check failed"
    kubectl exec -n ${NAMESPACE} deployment/api-gateway -- curl -f http://wiz-integration:8003/health || log_warning "Wiz Integration health check failed"
    kubectl exec -n ${NAMESPACE} deployment/api-gateway -- curl -f http://compliance-engine:8004/health || log_warning "Compliance Engine health check failed"
    
    log_success "Deployment verification completed"
}

# Display access information
display_access_info() {
    log_info "Deployment completed successfully!"
    echo
    echo "==================================================================="
    echo "AI-SPM Service Mesh Deployment Information"
    echo "==================================================================="
    echo
    echo "Namespace: ${NAMESPACE}"
    echo "Cluster: ${CLUSTER_NAME}"
    echo
    echo "External Access:"
    GATEWAY_IP=$(kubectl get service istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    echo "  Gateway IP: ${GATEWAY_IP}"
    echo "  Application URL: http://${GATEWAY_IP}/ (or configure DNS)"
    echo
    echo "Observability Dashboards:"
    echo "  Kiali: kubectl port-forward -n istio-system svc/kiali 20001:20001"
    echo "         Then access: http://localhost:20001"
    echo "  Grafana: kubectl port-forward -n istio-system svc/grafana 3000:3000"
    echo "           Then access: http://localhost:3000"
    echo "  Jaeger: kubectl port-forward -n istio-system svc/jaeger 16686:16686"
    echo "          Then access: http://localhost:16686"
    echo
    echo "Service Endpoints (internal):"
    echo "  API Gateway: http://api-gateway.ai-spm.svc.cluster.local:5000"
    echo "  AI Scanner: http://ai-scanner.ai-spm.svc.cluster.local:8001"
    echo "  Data Integrity: http://data-integrity.ai-spm.svc.cluster.local:8002"
    echo "  Wiz Integration: http://wiz-integration.ai-spm.svc.cluster.local:8003"
    echo "  Compliance Engine: http://compliance-engine.ai-spm.svc.cluster.local:8004"
    echo
    echo "Security Features:"
    echo "  ✓ mTLS enforced between all services"
    echo "  ✓ Authorization policies active"
    echo "  ✓ Distributed tracing enabled"
    echo "  ✓ Metrics collection enabled"
    echo
    echo "==================================================================="
}

# Main deployment function
main() {
    log_info "Starting AI-SPM Service Mesh deployment..."
    
    check_prerequisites
    install_istio
    install_istio_addons
    setup_namespace
    deploy_secrets
    deploy_storage
    deploy_configmaps
    deploy_applications
    deploy_security_policies
    deploy_traffic_management
    deploy_telemetry
    verify_deployment
    display_access_info
    
    log_success "AI-SPM Service Mesh deployment completed successfully!"
}

# Script options
case "${1:-deploy}" in
    deploy)
        main
        ;;
    cleanup)
        log_info "Cleaning up AI-SPM deployment..."
        kubectl delete namespace ${NAMESPACE} --ignore-not-found=true
        istioctl uninstall --purge -y
        kubectl delete namespace istio-system --ignore-not-found=true
        log_success "Cleanup completed"
        ;;
    verify)
        verify_deployment
        ;;
    *)
        echo "Usage: $0 {deploy|cleanup|verify}"
        echo "  deploy  - Deploy the complete AI-SPM service mesh"
        echo "  cleanup - Remove all AI-SPM and Istio resources"
        echo "  verify  - Verify the current deployment"
        exit 1
        ;;
esac