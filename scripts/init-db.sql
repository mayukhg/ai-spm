-- =============================================================================
-- AI Security Posture Management Platform - Database Initialization
-- =============================================================================
-- This script initializes the PostgreSQL database for the AI-SPM platform
-- in Docker containerized environments. It sets up the database schema,
-- indexes, and initial configuration for optimal performance.
-- =============================================================================

-- Create database if it doesn't exist (handled by POSTGRES_DB env var)
-- This script runs after the database is created

-- Set timezone for consistent timestamp handling
SET timezone = 'UTC';

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Performance Optimizations
-- =============================================================================

-- Increase work memory for better query performance
ALTER SYSTEM SET work_mem = '256MB';
ALTER SYSTEM SET shared_buffers = '512MB';
ALTER SYSTEM SET effective_cache_size = '2GB';

-- Optimize for containerized environment
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET checkpoint_completion_target = 0.9;

-- =============================================================================
-- Security Configuration
-- =============================================================================

-- Create application-specific role with limited privileges
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ai_spm_app') THEN
        CREATE ROLE ai_spm_app WITH LOGIN PASSWORD 'ai_spm_app_password';
    END IF;
END
$$;

-- Grant necessary permissions to application role
GRANT CONNECT ON DATABASE ai_spm_db TO ai_spm_app;
GRANT USAGE ON SCHEMA public TO ai_spm_app;
GRANT CREATE ON SCHEMA public TO ai_spm_app;

-- =============================================================================
-- Initial Schema Setup (if using raw SQL instead of Drizzle migrations)
-- =============================================================================
-- Note: The Node.js application uses Drizzle ORM which will handle schema
-- creation. This section provides backup SQL for manual setup if needed.

-- Users table for authentication and authorization
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'analyst',
    name VARCHAR(255),
    department VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(255)
);

-- AI Assets table for comprehensive asset management
CREATE TABLE IF NOT EXISTS ai_assets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    asset_type VARCHAR(50) NOT NULL, -- 'model', 'dataset', 'pipeline', 'endpoint'
    environment VARCHAR(50) NOT NULL, -- 'development', 'staging', 'production'
    status VARCHAR(50) DEFAULT 'active',
    risk_level VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    owner_id INTEGER REFERENCES users(id),
    department VARCHAR(100),
    location VARCHAR(255),
    version VARCHAR(50),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerabilities table for security tracking
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    status VARCHAR(50) DEFAULT 'open', -- 'open', 'in_progress', 'resolved', 'false_positive'
    cve_id VARCHAR(50),
    asset_id INTEGER REFERENCES ai_assets(id),
    assigned_to INTEGER REFERENCES users(id),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    due_date TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Security Alerts table for real-time monitoring
CREATE TABLE IF NOT EXISTS security_alerts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    source VARCHAR(100),
    asset_id INTEGER REFERENCES ai_assets(id),
    metadata JSONB,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Audit Logs table for compliance tracking
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(50),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- Performance Indexes
-- =============================================================================

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_department ON users(department);

-- AI Assets table indexes
CREATE INDEX IF NOT EXISTS idx_ai_assets_type ON ai_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_ai_assets_environment ON ai_assets(environment);
CREATE INDEX IF NOT EXISTS idx_ai_assets_status ON ai_assets(status);
CREATE INDEX IF NOT EXISTS idx_ai_assets_risk_level ON ai_assets(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_assets_owner ON ai_assets(owner_id);
CREATE INDEX IF NOT EXISTS idx_ai_assets_department ON ai_assets(department);
CREATE INDEX IF NOT EXISTS idx_ai_assets_created_at ON ai_assets(created_at);

-- Vulnerabilities table indexes
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset ON vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_assigned ON vulnerabilities(assigned_to);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_discovered ON vulnerabilities(discovered_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_due_date ON vulnerabilities(due_date);

-- Security Alerts table indexes
CREATE INDEX IF NOT EXISTS idx_security_alerts_type ON security_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_asset ON security_alerts(asset_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_triggered ON security_alerts(triggered_at);

-- Audit Logs table indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- =============================================================================
-- Trigger Functions for Automatic Timestamps
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to tables with updated_at columns
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_ai_assets_updated_at BEFORE UPDATE ON ai_assets FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Initial Data for Development and Testing
-- =============================================================================

-- Insert default admin user (password: admin123)
INSERT INTO users (email, password_hash, role, name, department, is_active) VALUES 
('admin@ai-spm.com', '$2b$10$rQZ9QmZ9QmZ9QmZ9QmZ9Qu', 'ciso', 'System Administrator', 'Security', true)
ON CONFLICT (email) DO NOTHING;

-- Insert sample compliance frameworks (if not using Drizzle seed data)
-- This would be handled by the application initialization

-- =============================================================================
-- Database Maintenance Functions
-- =============================================================================

-- Function to clean up old audit logs (retain 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs 
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to update asset risk levels based on vulnerability count
CREATE OR REPLACE FUNCTION update_asset_risk_levels()
RETURNS VOID AS $$
BEGIN
    UPDATE ai_assets 
    SET risk_level = CASE 
        WHEN (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = ai_assets.id AND v.severity = 'critical' AND v.status = 'open') > 0 THEN 'critical'
        WHEN (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = ai_assets.id AND v.severity = 'high' AND v.status = 'open') > 2 THEN 'high'
        WHEN (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = ai_assets.id AND v.severity IN ('high', 'medium') AND v.status = 'open') > 5 THEN 'high'
        WHEN (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = ai_assets.id AND v.status = 'open') > 0 THEN 'medium'
        ELSE 'low'
    END,
    updated_at = CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Grant Permissions to Application Role
-- =============================================================================

-- Grant permissions on all tables to application role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ai_spm_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ai_spm_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ai_spm_app;

-- Grant permissions on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ai_spm_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ai_spm_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO ai_spm_app;

-- =============================================================================
-- Completion Message
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE 'AI-SPM Database initialization completed successfully!';
    RAISE NOTICE 'Database: ai_spm_db';
    RAISE NOTICE 'Application role: ai_spm_app';
    RAISE NOTICE 'Extensions enabled: uuid-ossp, pgcrypto';
    RAISE NOTICE 'Performance optimizations applied';
    RAISE NOTICE 'Ready for Drizzle ORM schema management';
END $$;