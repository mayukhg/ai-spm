import "dotenv/config";
// Phoenix Option 1 tracing — must load before OpenAI/OpenRouter client imports
import { shutdownPhoenixTracing } from "./observability/tracer";
import express, { type Request, Response, NextFunction } from "express";
import session from 'express-session';
import passport from 'passport';
import helmet from 'helmet';
import cors from 'cors';
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { authRoutes } from './routes/auth-routes';
import { securityRoutes } from './routes/security-routes';
import { agenticRoutes } from './routes/agentic-routes';
import { monitoringRoutes } from './routes/monitoring-routes';
import { threatConfigRoutes } from './routes/threat-config-routes';
import complianceRoutes from './routes/compliance-routes';
import { startResidentAgent, stopResidentAgent } from './governance/resident-agent';

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
    },
  },
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || `http://localhost:${process.env.PORT || 5000}`,
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'ai-spm-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Request logging and correlation ID middleware
app.use((req, res, next) => {
  const correlationId = req.headers['x-correlation-id'] || 
                       req.headers['x-request-id'] || 
                       `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  req.headers['x-correlation-id'] = correlationId;
  res.setHeader('x-correlation-id', correlationId);
  
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    services: {
      authentication: 'operational',
      security: 'operational',
      privacy: 'operational',
      modelSecurity: 'operational',
    },
    version: '1.0.0',
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/agentic', agenticRoutes);
app.use('/api/monitoring', monitoringRoutes);
app.use('/api/threat-config', threatConfigRoutes);
app.use('/api/compliance', complianceRoutes);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Application error:', err);
  
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    correlationId: req.headers['x-correlation-id'],
    timestamp: new Date().toISOString(),
  });
});

(async () => {
  const server = await registerRoutes(app);

  // Registered after application routes so it does not swallow them.
  app.use('/api/*', (req, res) => {
    res.status(404).json({
      error: 'API endpoint not found',
      path: req.path,
      correlationId: req.headers['x-correlation-id'],
    });
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Serves both the API and the client. PORT overrides the default so local
  // macOS can avoid the AirPlay listener on 5000.
  const port = Number(process.env.PORT) || 5000;
  server.listen({
    port,
    host: "0.0.0.0",
  }, () => {
    log(`AI-SPM Platform serving on port ${port}`);
    log(`Security features: Authentication, SIEM, Model Security, Privacy Governance`);
    log(`Resident agent: Practical Fast Math (15m interval, Isolation Forest + LOF + KS)`);
    
    if (process.env.OAUTH_CLIENT_ID) {
      log(`OAuth 2.0/OpenID Connect enabled`);
    }
    
    if (process.env.SAML_ENTRY_POINT) {
      log(`SAML authentication enabled`);
    }
    
    if (process.env.SPLUNK_ENDPOINT) {
      log(`Splunk SIEM integration enabled`);
    }

    if (process.env.OPENROUTER_API_KEY) {
      log(`OpenRouter async governance reports enabled (${process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini"})`);
    } else {
      log(`OpenRouter key not set — async GDPR/NIST reports will prompt for OPENROUTER_API_KEY`);
    }

    // Continuous Automated Health: start the resident monitor after listen
    if (process.env.RESIDENT_AGENT !== "false") {
      startResidentAgent();
    }

    let shuttingDown = false;
    const gracefulShutdown = async (signal: string) => {
      if (shuttingDown) return;
      shuttingDown = true;
      log(`Received ${signal} — stopping resident agent, HTTP server, Phoenix tracer`);
      try {
        stopResidentAgent();
      } catch (err) {
        console.error("Resident agent stop error:", err);
      }
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 4000);
        server.close(() => {
          clearTimeout(timer);
          resolve();
        });
      });
      try {
        await shutdownPhoenixTracing();
      } catch (err) {
        console.error("Phoenix tracer shutdown error:", err);
      }
      process.exit(0);
    };
    process.once("SIGTERM", () => {
      void gracefulShutdown("SIGTERM");
    });
    process.once("SIGINT", () => {
      void gracefulShutdown("SIGINT");
    });
  });
})().catch((err) => {
  console.error("Failed to start AI-SPM server:", err);
  process.exit(1);
});
