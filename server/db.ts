import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "@shared/schema";

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

// Standard Postgres wire protocol. Works with local Docker Postgres and with
// a direct Neon connection string. connect-pg-simple also requires a node-pg Pool.
export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export const db = drizzle(pool, { schema });
