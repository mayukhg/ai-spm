-- Database extensions for a fresh Postgres volume.
-- Table definitions live in shared/schema.ts and are applied with drizzle-kit.
-- This script no longer creates a second, conflicting users table.

SET timezone = 'UTC';

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
