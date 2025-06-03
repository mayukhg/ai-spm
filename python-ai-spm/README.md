# AI Security Posture Management Platform (Python)

A comprehensive enterprise-grade security management platform designed specifically for AI/ML systems, built with Flask and PostgreSQL. This platform provides complete lifecycle security management for AI assets including vulnerability assessment, compliance monitoring, and threat detection.

## Features

### 🛡️ Comprehensive Security Management
- **AI Asset Inventory**: Complete lifecycle tracking of models, datasets, pipelines, and APIs
- **Vulnerability Assessment**: Automated scanning and manual assessment with risk scoring
- **Threat Detection**: Real-time security alert monitoring and incident response
- **Risk Analytics**: Advanced risk scoring with predictive threat modeling

### 📋 Compliance & Governance
- **Regulatory Compliance**: Built-in support for NIST AI RMF, ISO 27001, SOC 2, GDPR
- **Policy Management**: Automated governance policy enforcement and monitoring
- **Audit Trail**: Comprehensive logging for compliance and forensic analysis
- **Assessment Workflows**: Structured compliance assessment and reporting

### 🔗 Enterprise Integration
- **Wiz Security Platform**: Native integration for cloud security data import
- **Role-Based Access Control**: Granular permissions for different user roles
- **Multi-Factor Authentication**: Enhanced security with TOTP support
- **API-First Design**: RESTful APIs for custom integrations

### 📊 Analytics & Reporting
- **Security Dashboard**: Real-time metrics and executive reporting
- **Custom Reports**: Automated compliance and security reporting
- **Trend Analysis**: Historical data analysis and predictive insights
- **KPI Monitoring**: Key performance indicators for security posture

## Technology Stack

### Backend
- **Flask 2.3+** - Modern Python web framework
- **SQLAlchemy 2.0+** - Advanced ORM with type safety
- **PostgreSQL** - Enterprise-grade relational database
- **Celery** - Distributed task queue for background jobs
- **Redis** - Caching and message broker

### Security
- **Werkzeug** - Secure password hashing
- **PyJWT** - JSON Web Token implementation
- **PyOTP** - Multi-factor authentication support
- **Cryptography** - Modern cryptographic library

### Integration
- **Requests** - HTTP client for external API integration
- **Wiz GraphQL API** - Cloud security platform integration

## Installation & Setup

### Prerequisites
- Python 3.9 or higher
- PostgreSQL 13 or higher
- Redis server (optional, for caching and background tasks)

### Environment Setup

1. **Clone and Setup Virtual Environment**
```bash
git clone <repository-url>
cd python-ai-spm
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Environment Configuration**

Create a `.env` file in the project root:

```bash
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/ai_spm_db
SQLALCHEMY_DATABASE_URI=postgresql://username:password@localhost:5432/ai_spm_db

# Security Settings
SESSION_SECRET=your-session-secret
JWT_SECRET_KEY=your-jwt-secret

# Wiz Integration (Optional)
WIZ_CLIENT_ID=your-wiz-client-id
WIZ_CLIENT_SECRET=your-wiz-client-secret
WIZ_AUTH_URL=https://auth.app.wiz.io/oauth/token
WIZ_API_URL=https://api.us1.app.wiz.io/graphql
WIZ_AUDIENCE=wiz-api

# Email Configuration (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-email-password

# Redis Configuration (Optional)
REDIS_URL=redis://localhost:6379/0

# Logging
LOG_LEVEL=INFO
LOG_FILE=ai_spm.log
```

4. **Database Setup**
```bash
# Create PostgreSQL database
createdb ai_spm_db

# Initialize database tables
python -c "from app import create_app; from models import db; app = create_app(); app.app_context().push(); db.create_all()"
```

5. **Run Application**
```bash
# Development server
python app.py

# Production server (using Gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

The application will be available at `http://localhost:5000`

## API Documentation

### Authentication Endpoints

#### User Registration
```http
POST /auth/register
Content-Type: application/json

{
  "username": "string",
  "email": "string",
  "password": "string",
  "first_name": "string",
  "last_name": "string",
  "department": "string",
  "role": "analyst"
}
```

#### User Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string",
  "mfa_code": "string (optional)"
}
```

#### Logout
```http
POST /auth/logout
```

### Asset Management Endpoints

#### Get Assets
```http
GET /api/assets?page=1&per_page=20&asset_type=model&environment=production
```

#### Create Asset
```http
POST /api/assets
Content-Type: application/json

{
  "name": "string",
  "description": "string",
  "asset_type": "model|dataset|pipeline|api|infrastructure|endpoint",
  "environment": "development|staging|production|research",
  "owner_id": "integer",
  "department": "string",
  "cloud_provider": "string",
  "region": "string"
}
```

#### Get Asset Details
```http
GET /api/assets/{asset_id}
```

### Vulnerability Management Endpoints

#### Get Vulnerabilities
```http
GET /api/vulnerabilities?severity=critical&status=open&asset_id=1
```

#### Create Vulnerability
```http
POST /api/vulnerabilities
Content-Type: application/json

{
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low|informational",
  "asset_id": "integer",
  "cve_id": "string (optional)",
  "cvss_score": "number (optional)"
}
```

#### Get Vulnerability Statistics
```http
GET /api/vulnerabilities/stats
```

### Security Alert Endpoints

#### Get Security Alerts
```http
GET /api/security-alerts?severity=high&status=open
```

#### Get Recent Alerts
```http
GET /api/security-alerts/recent?limit=10
```

### Dashboard Endpoints

#### Get Dashboard Metrics
```http
GET /api/dashboard/metrics
```

### Compliance Endpoints

#### Get Compliance Frameworks
```http
GET /api/compliance/frameworks
```

#### Get Compliance Overview
```http
GET /api/compliance/overview
```

### Audit Log Endpoints (Admin Only)

#### Get Audit Logs
```http
GET /api/audit-logs?user_id=1&action=login&start_date=2024-01-01
```

## Wiz Integration

### Setup

1. **Obtain Wiz API Credentials**
   - Contact your Wiz administrator
   - Create a service account in Wiz console > Settings > Service Accounts
   - Note the Client ID and Client Secret

2. **Configure Environment Variables**
```bash
WIZ_CLIENT_ID=your-wiz-client-id
WIZ_CLIENT_SECRET=your-wiz-client-secret
WIZ_AUDIENCE=wiz-api
```

3. **Test Integration**
```python
from integrations.wiz_integration import create_wiz_integration

# Create integration instance
wiz_sync = create_wiz_integration()

if wiz_sync:
    # Test asset sync
    result = wiz_sync.sync_assets({'limit': 10})
    print(f"Synced {result['imported']} assets")
```

### Sync Operations

#### Asset Sync
```python
# Sync all assets
result = wiz_sync.sync_assets()

# Sync with filters
result = wiz_sync.sync_assets({
    'cloud_platform': 'AWS',
    'subscription_id': 'your-subscription-id',
    'limit': 100
})
```

#### Vulnerability Sync
```python
# Sync vulnerabilities
result = wiz_sync.sync_vulnerabilities({
    'severity': ['CRITICAL', 'HIGH'],
    'status': ['OPEN', 'IN_PROGRESS'],
    'limit': 50
})
```

#### Full Sync
```python
# Complete data synchronization
result = wiz_sync.full_sync({
    'asset_filters': {'cloud_platform': 'AWS'},
    'vuln_filters': {'severity': ['CRITICAL', 'HIGH']},
    'alert_filters': {'severity': ['CRITICAL']},
    'owner_id': 1
})
```

## User Roles and Permissions

### Role Hierarchy
1. **Admin** - Full system access
2. **CISO** - Security leadership access
3. **Compliance Officer** - Compliance and audit access
4. **Analyst** - Security analysis and reporting
5. **Engineer** - Asset management and technical access
6. **Auditor** - Read-only audit access

### Permission Matrix

| Resource | Admin | CISO | Compliance | Analyst | Engineer | Auditor |
|----------|-------|------|------------|---------|----------|---------|
| Assets | CRUD | CRU | R | RU | CRU | R |
| Vulnerabilities | CRUD | CRU | R | CRU | RU | R |
| Compliance | CRUD | CRU | CRU | R | R | R |
| Users | CRUD | RU | R | R | R | R |
| Audit Logs | R | R | R | - | - | R |

*CRUD = Create, Read, Update, Delete*

## Development

### Code Structure
```
python-ai-spm/
├── app.py                 # Main application factory
├── config.py              # Configuration management
├── models.py              # Database models and schemas
├── auth.py                # Authentication and authorization
├── api.py                 # REST API endpoints
├── integrations/          # External system integrations
│   └── wiz_integration.py # Wiz platform integration
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-flask pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html
```

### Code Quality
```bash
# Format code
black .

# Sort imports
isort .

# Lint code
flake8 .

# Type checking
mypy .
```

### Database Migrations
```bash
# Create migration
alembic revision --autogenerate -m "Description of changes"

# Apply migration
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## Production Deployment

### Using Gunicorn
```bash
# Install Gunicorn
pip install gunicorn

# Run with multiple workers
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 app:app

# With configuration file
gunicorn -c gunicorn.conf.py app:app
```

### Docker Deployment
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

### Environment Variables for Production
```bash
# Security
FLASK_ENV=production
SECRET_KEY=production-secret-key
SESSION_SECRET=production-session-secret

# Database
DATABASE_URL=postgresql://user:pass@db-host:5432/ai_spm_prod

# Monitoring
SENTRY_DSN=your-sentry-dsn
LOG_LEVEL=WARNING
```

## Monitoring and Logging

### Application Logs
- Structured logging with JSON format
- Configurable log levels
- Audit trail for compliance
- Error tracking with Sentry integration

### Health Checks
```http
GET /health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "database": "healthy",
  "metrics": {
    "total_assets": 150,
    "critical_vulnerabilities": 5,
    "active_alerts": 10
  }
}
```

## Security Considerations

### Authentication
- Secure password hashing with Werkzeug
- Multi-factor authentication support
- Session management with secure cookies
- Rate limiting for login attempts

### Data Protection
- SQL injection prevention with SQLAlchemy ORM
- XSS protection with proper output encoding
- CSRF protection for state-changing operations
- Secure HTTP headers for all responses

### API Security
- Role-based access control
- Request validation and sanitization
- Audit logging for all actions
- Rate limiting for API endpoints

## Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check database status
pg_isready -h localhost -p 5432

# Test connection
python -c "from models import db; from app import create_app; app = create_app(); app.app_context().push(); db.session.execute('SELECT 1')"
```

#### Wiz Integration Issues
```bash
# Test Wiz credentials
python -c "from integrations.wiz_integration import create_wiz_integration; print('OK' if create_wiz_integration() else 'FAILED')"
```

#### Permission Errors
- Verify user roles in database
- Check API endpoint role requirements
- Review audit logs for access attempts

### Debug Mode
```bash
# Enable debug logging
export FLASK_ENV=development
export LOG_LEVEL=DEBUG
python app.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with proper tests
4. Follow code style guidelines
5. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For technical support and questions:
- Email: support@ai-spm.com
- Documentation: https://docs.ai-spm.com
- Issues: https://github.com/ai-spm/python-platform/issues

---

Built with ❤️ for enterprise AI security