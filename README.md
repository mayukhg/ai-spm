# AI Security Posture Management (AI-SPM) Platform

A comprehensive enterprise-grade security platform designed to manage, monitor, and secure AI/ML assets throughout their lifecycle. The platform provides real-time threat detection, vulnerability management, compliance monitoring, and governance controls for AI systems.

## Features

### 🛡️ Core Security Capabilities
- **AI Asset Discovery & Inventory**: Automated discovery and cataloging of AI models, datasets, pipelines, and endpoints
- **Vulnerability Management**: Continuous security scanning with risk assessment and remediation tracking
- **Real-time Threat Monitoring**: 24/7 monitoring with anomaly detection and automated alerting
- **Security Incident Response**: Centralized incident management with workflow automation

### 📊 Compliance & Governance
- **Multi-Framework Compliance**: Support for NIST AI RMF, GDPR, SOC 2, ISO 27001
- **Automated Assessments**: Continuous compliance monitoring with scoring and reporting
- **Policy Management**: Centralized governance policies with enforcement capabilities
- **Audit Trail**: Comprehensive logging of all system activities and user actions

### 📈 Analytics & Reporting
- **Security Dashboard**: Real-time metrics, trend analysis, and executive reporting
- **Risk Analytics**: Advanced risk scoring and predictive threat modeling
- **Compliance Reporting**: Automated generation of compliance reports and certifications
- **Custom Dashboards**: Role-based views with personalized security insights

### 👥 Enterprise Features
- **Role-Based Access Control**: Granular permissions for different user roles and departments
- **Multi-Tenant Support**: Isolated environments for different business units
- **Integration Ready**: APIs for third-party security tools and enterprise systems
- **Scalable Architecture**: Designed for enterprise-scale deployments

## Technology Stack

### Frontend
- **React 18** - Modern component-based UI framework
- **TypeScript** - Type-safe development with enhanced developer experience
- **Tailwind CSS** - Utility-first styling with responsive design
- **Shadcn/UI** - Production-ready component library
- **TanStack Query** - Powerful data synchronization and caching
- **React Hook Form** - Performant forms with validation
- **Recharts** - Interactive data visualization

### Backend
- **Node.js** - High-performance JavaScript runtime
- **Express.js** - Fast, unopinionated web framework
- **TypeScript** - End-to-end type safety
- **Passport.js** - Comprehensive authentication strategies
- **Drizzle ORM** - Type-safe database operations
- **PostgreSQL** - Enterprise-grade relational database
- **Zod** - Runtime type validation and parsing

## Project Structure

```
├── client/                 # Frontend React application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   │   ├── charts/     # Data visualization components
│   │   │   ├── layout/     # Layout components (sidebar, header)
│   │   │   └── ui/         # Base UI components (shadcn)
│   │   ├── hooks/          # Custom React hooks
│   │   │   ├── use-auth.tsx      # Authentication context
│   │   │   ├── use-toast.ts      # Toast notifications
│   │   │   └── use-mobile.tsx    # Mobile detection
│   │   ├── lib/            # Utility libraries
│   │   │   ├── queryClient.ts    # API client configuration
│   │   │   ├── utils.ts          # Common utilities
│   │   │   └── protected-route.tsx # Route protection
│   │   ├── pages/          # Application pages
│   │   │   ├── dashboard.tsx     # Main dashboard
│   │   │   ├── ai-assets.tsx     # Asset management
│   │   │   ├── vulnerabilities.tsx # Vulnerability tracking
│   │   │   ├── compliance.tsx    # Compliance management
│   │   │   ├── monitoring.tsx    # Real-time monitoring
│   │   │   └── auth-page.tsx     # Authentication
│   │   └── types/          # TypeScript type definitions
├── server/                 # Backend Express application
│   ├── auth.ts            # Authentication middleware
│   ├── db.ts              # Database connection
│   ├── routes.ts          # API route definitions
│   ├── storage.ts         # Data access layer
│   ├── index.ts           # Server entry point
│   └── vite.ts            # Development server setup
├── shared/                # Shared code between client/server
│   └── schema.ts          # Database schema and validation
├── ARCHITECTURE.md        # Detailed system architecture
└── package.json           # Dependencies and scripts
```

## Database Schema

### Core Entities

**Users**: User accounts with role-based permissions
- Roles: Security Analyst, AI/ML Engineer, Compliance Officer, CISO
- Attributes: credentials, profile information, department assignment

**AI Assets**: Comprehensive asset inventory
- Types: Models, Datasets, Pipelines, Endpoints
- Environments: Development, Staging, Production
- Metadata: ownership, dependencies, risk levels, compliance status

**Vulnerabilities**: Security findings and remediation tracking
- Severity levels: Critical, High, Medium, Low
- Status tracking: Open, In Progress, Resolved, False Positive
- Assignment and escalation workflows

**Security Alerts**: Real-time threat notifications
- Incident categorization and prioritization
- Automated response triggers
- Integration with external security tools

**Compliance Frameworks**: Regulatory and standards compliance
- Framework definitions: NIST AI RMF, GDPR, SOC 2, ISO 27001
- Assessment templates and scoring criteria
- Automated compliance monitoring

**Audit Logs**: Comprehensive activity tracking
- User actions and system events
- Data access and modification logs
- Compliance audit trails

## API Reference

### Authentication Endpoints
```
POST /api/register        # User registration
POST /api/login          # User authentication
POST /api/logout         # Session termination
GET  /api/user           # Current user information
```

### AI Asset Management
```
GET    /api/ai-assets              # List all assets (with filtering)
POST   /api/ai-assets              # Create new asset
GET    /api/ai-assets/:id          # Get asset details
PUT    /api/ai-assets/:id          # Update asset
DELETE /api/ai-assets/:id          # Delete asset
GET    /api/ai-assets/owner/:owner # Get assets by owner
```

### Vulnerability Management
```
GET  /api/vulnerabilities           # List vulnerabilities (with filtering)
POST /api/vulnerabilities          # Report new vulnerability
GET  /api/vulnerabilities/:id      # Get vulnerability details
PUT  /api/vulnerabilities/:id      # Update vulnerability status
GET  /api/vulnerabilities/stats    # Get vulnerability statistics
GET  /api/vulnerabilities/asset/:id # Get vulnerabilities for asset
```

### Security Monitoring
```
GET  /api/security-alerts          # List security alerts
POST /api/security-alerts          # Create security alert
PUT  /api/security-alerts/:id      # Update alert status
GET  /api/security-alerts/recent   # Get recent alerts
```

### Compliance Management
```
GET  /api/compliance/frameworks        # List compliance frameworks
POST /api/compliance/frameworks        # Create framework
GET  /api/compliance/assessments       # List assessments
POST /api/compliance/assessments       # Create assessment
GET  /api/compliance/overview          # Compliance dashboard data
```

### Dashboard & Analytics
```
GET  /api/dashboard/metrics         # Dashboard statistics
GET  /api/audit-logs               # System audit logs
```

## Installation & Setup

### Prerequisites
- Node.js 18+ 
- PostgreSQL 13+
- npm or yarn package manager

### Environment Configuration
Create a `.env` file with the following variables:
```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/ai_spm
PGHOST=localhost
PGPORT=5432
PGUSER=your_db_user
PGPASSWORD=your_db_password
PGDATABASE=ai_spm

# Authentication
SESSION_SECRET=your_session_secret_key

# Application
NODE_ENV=development
PORT=5000
```

### Installation Steps

1. **Clone and Install Dependencies**
```bash
git clone <repository-url>
cd ai-spm-platform
npm install
```

2. **Database Setup**
```bash
# Create PostgreSQL database
createdb ai_spm

# Push database schema
npm run db:push
```

3. **Start Development Server**
```bash
npm run dev
```

The application will be available at `http://localhost:5000`

### Production Deployment

1. **Build Application**
```bash
npm run build
```

2. **Start Production Server**
```bash
npm start
```

## Usage Guide

### Initial Setup

1. **Access the Application**: Navigate to the application URL
2. **Create Admin Account**: Register the first user (will have admin privileges)
3. **Configure Organization**: Set up departments and user roles
4. **Import AI Assets**: Begin asset discovery and inventory

### User Roles & Permissions

**Security Analyst**
- Monitor vulnerabilities and security alerts
- Investigate security incidents
- Generate security reports

**AI/ML Engineer** 
- Manage AI assets and deployments
- Monitor model performance and behavior
- Implement security recommendations

**Compliance Officer**
- Oversee compliance assessments
- Generate compliance reports
- Manage governance policies

**CISO (Chief Information Security Officer)**
- Executive dashboard access
- Organization-wide security oversight
- Strategic security planning

### Key Workflows

**Asset Onboarding**
1. Navigate to AI Assets section
2. Click "Add New Asset"
3. Complete asset registration form
4. Assign ownership and environment
5. Configure monitoring settings

**Vulnerability Management**
1. Review vulnerability dashboard
2. Assign vulnerabilities to team members
3. Track remediation progress
4. Validate fixes and close tickets

**Compliance Monitoring**
1. Select compliance framework
2. Configure assessment parameters
3. Run automated compliance scans
4. Review results and generate reports

## Security Features

### Authentication & Authorization
- Session-based authentication with secure session management
- Role-based access control (RBAC) with granular permissions
- Multi-factor authentication support (extensible)
- Account lockout protection against brute force attacks

### Data Protection
- Password hashing using scrypt with salt
- SQL injection prevention via parameterized queries
- Cross-site scripting (XSS) protection
- Cross-site request forgery (CSRF) protection
- Input validation and sanitization

### Audit & Compliance
- Comprehensive audit logging of all user actions
- Data retention policies for compliance requirements
- Encrypted data storage for sensitive information
- Regular security assessments and vulnerability scanning

## Monitoring & Observability

### Application Monitoring
- Real-time application performance metrics
- Database query performance monitoring
- Error tracking and alerting
- User activity analytics

### Security Monitoring
- Failed authentication attempt tracking
- Suspicious activity detection
- Automated security alert generation
- Integration with SIEM systems

### Health Checks
- Application health endpoints
- Database connectivity monitoring
- Service dependency checks
- Automated failover capabilities

## Troubleshooting

### Common Issues

**Database Connection Errors**
- Verify PostgreSQL service is running
- Check database connection credentials
- Ensure database exists and is accessible

**Authentication Problems**
- Clear browser cache and cookies
- Verify session store configuration
- Check user credentials and account status

**Performance Issues**
- Monitor database query performance
- Check memory and CPU usage
- Review application logs for errors

### Support & Maintenance

**Log Files**
- Application logs: `logs/app.log`
- Error logs: `logs/error.log`
- Audit logs: Database audit_logs table

**Database Maintenance**
```bash
# Backup database
pg_dump ai_spm > backup.sql

# Restore database
psql ai_spm < backup.sql

# Update database schema
npm run db:push
```

## Contributing

### Development Guidelines
- Follow TypeScript best practices
- Implement comprehensive error handling
- Write unit and integration tests
- Document API changes and new features

### Code Quality
- ESLint configuration for code standards
- Prettier for consistent formatting
- Type safety with strict TypeScript configuration
- Security scanning with automated tools

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For technical support, feature requests, or bug reports, please contact:
- Technical Support: support@ai-spm.com
- Documentation: docs@ai-spm.com
- Security Issues: security@ai-spm.com

---

Built with ❤️ for enterprise AI security