# AI Security Posture Management (AI-SPM) Platform

## Overview

The AI Security Posture Management Platform is an enterprise-grade security solution designed to manage and monitor AI/ML assets throughout their lifecycle. This platform provides comprehensive security governance for AI systems from development to production deployment, offering features like asset discovery, vulnerability management, compliance monitoring, and threat detection.

## System Architecture

The platform implements a **hybrid microservices architecture with Istio service mesh** that combines Node.js for web services with Python for specialized AI/ML tasks:

### Primary Architecture Components
- **Istio Service Mesh**: Provides automatic mTLS, traffic management, and observability
- **Node.js API Gateway**: Handles web requests, authentication, frontend serving, and data management
- **React Frontend**: Modern responsive UI built with shadcn/ui components and TypeScript
- **Python Microservices**: Four specialized FastAPI services for AI-specific processing
- **PostgreSQL Database**: Centralized data storage with Drizzle ORM integration

### Service Mesh Security Features
- **Automatic mTLS**: All inter-service communication encrypted and authenticated
- **Zero Trust Security**: Services communicate only through verified certificates
- **Authorization Policies**: Fine-grained access control between services
- **Observability**: Distributed tracing, metrics collection, and access logging

### Microservices Structure
1. **AI Scanner Service** (Port 8001): Model security analysis and bias detection
2. **Data Integrity Service** (Port 8002): Data quality checks and anomaly detection  
3. **Wiz Integration Service** (Port 8003): External API data transformation and security alert processing
4. **Compliance Engine** (Port 8004): Policy evaluation and automated assessments

## Key Components

### Frontend (React + TypeScript)
- **Framework**: React 18 with TypeScript for type safety
- **UI Library**: shadcn/ui components built on Radix UI primitives
- **Styling**: Tailwind CSS with custom design system
- **State Management**: TanStack Query for server state management
- **Routing**: Wouter for lightweight client-side routing
- **Authentication**: Session-based authentication with role-based access control

### Backend (Node.js + Express)
- **Runtime**: Node.js 18+ with TypeScript
- **Framework**: Express.js for API routes and middleware
- **Authentication**: Passport.js with local strategy and session management
- **Database ORM**: Drizzle ORM with PostgreSQL adapter
- **Security**: Comprehensive input validation, rate limiting, and CORS configuration
- **Session Store**: PostgreSQL-backed session storage for persistence

### Database Schema (PostgreSQL)
- **Users**: Authentication and role management (CISO, analyst, engineer, compliance officer)
- **AI Assets**: Models, datasets, APIs, and pipelines with metadata
- **Vulnerabilities**: Security findings with severity classification and remediation tracking
- **Security Alerts**: Real-time threat notifications and incident management
- **Compliance**: Frameworks, assessments, and governance policies
- **Audit Logs**: Comprehensive activity tracking for compliance

### Python Microservices (FastAPI)
Each microservice is containerized and provides specialized capabilities:
- **Async Processing**: FastAPI with async/await patterns for high performance
- **API Documentation**: Auto-generated OpenAPI/Swagger documentation
- **Health Monitoring**: Built-in health check endpoints
- **Error Handling**: Comprehensive error handling with structured logging

## Data Flow

### Authentication Flow
1. User submits credentials via React frontend
2. Express backend validates against PostgreSQL user store
3. Session created and stored in PostgreSQL
4. User context maintained across requests via session middleware

### Asset Management Flow
1. Assets discovered manually or via automated scanning
2. Node.js API Gateway handles CRUD operations
3. Python microservices process specialized tasks (scanning, compliance checks)
4. Results stored in PostgreSQL and reflected in React dashboard

### Microservice Communication
1. Node.js gateway receives API requests
2. Requests routed to appropriate Python microservices via HTTP
3. Microservices process data and return results
4. Gateway aggregates responses and updates database
5. Frontend receives real-time updates via polling or WebSocket connections

## External Dependencies

### Core Dependencies
- **Node.js**: Runtime environment (v18+)
- **PostgreSQL**: Primary database (v12+)
- **Python**: Microservices runtime (v3.11+)

### Key NPM Packages
- **Express.js**: Web framework and API server
- **Drizzle ORM**: Type-safe database operations
- **Passport.js**: Authentication middleware
- **React**: Frontend framework with TypeScript
- **TanStack Query**: Server state management
- **shadcn/ui**: UI component library

### Python Dependencies
- **FastAPI**: Modern async web framework
- **SQLAlchemy**: Database ORM for Python services
- **Pydantic**: Data validation and serialization
- **Uvicorn**: ASGI server for FastAPI applications

### External Integrations
- **Wiz Security Platform**: Cloud security data import via GraphQL API
- **CORS**: Cross-origin resource sharing for frontend-backend communication

## Deployment Strategy

### Development Environment
- **Local Development**: npm run dev starts Node.js gateway with hot reload
- **Database**: Local PostgreSQL instance or cloud database
- **Microservices**: Optional - can run standalone or mocked

### Containerization (Docker)
- **Multi-stage Dockerfile**: Optimized builds for Node.js and Python services
- **Docker Compose**: Orchestrates full stack deployment
- **Health Checks**: Built-in health monitoring for all services
- **Volume Mounts**: Persistent data storage for PostgreSQL

### Cloud Deployment
- **AWS CloudFormation**: Infrastructure as code template provided
- **ECS Fargate**: Serverless container deployment
- **RDS PostgreSQL**: Managed database service
- **Application Load Balancer**: Traffic distribution and SSL termination

### Environment Configuration
- **Environment Variables**: Centralized configuration via .env files
- **Database URLs**: Support for various PostgreSQL connection formats
- **Service Discovery**: Configurable microservice endpoints
- **Security**: Separate secrets management for production

## Changelog

- June 24, 2025. Initial hybrid microservices architecture setup
- June 24, 2025. Implemented Istio service mesh with mTLS and authorization policies
- June 24, 2025. **MAJOR ENHANCEMENT**: Implemented comprehensive security and AI/ML features:
  * Advanced Authentication & Authorization (OAuth 2.0, SAML, WebAuthn/FIDO2)
  * Enhanced Security Monitoring with real-time event correlation and SIEM integration
  * AI/ML Security Features including model versioning, bias detection, and vulnerability scanning
  * Data Privacy & Governance with automated PII detection and GDPR/CCPA compliance
  * Updated all documentation to reflect enhanced capabilities
- June 24, 2025. **AGENTIC WORKFLOWS DESIGN**: Designed comprehensive agent-based workflow support:
  * Model Context Protocol (MCP) integration with security controls
  * Agent orchestration service with behavioral monitoring
  * Agentic compliance framework for regulatory adherence
  * Context security and anomaly detection for autonomous agents

## User Preferences

Preferred communication style: Simple, everyday language.