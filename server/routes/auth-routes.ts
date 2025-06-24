import express from 'express';
import passport from 'passport';
import { AuthenticationProvider, WebAuthnProvider } from '../auth/oauth-provider';
import { SecurityEventCorrelationEngine } from '../security/siem-integration';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
});

const webauthnLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // 10 attempts per window
});

// Initialize providers
const authProvider = new AuthenticationProvider({
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback-secret',
    issuer: 'ai-spm-platform',
    audience: 'ai-spm-users',
    algorithm: 'HS256',
    expiresIn: '1h',
  },
  oauth: process.env.OAUTH_CLIENT_ID ? {
    clientID: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET!,
    authorizationURL: process.env.OAUTH_AUTH_URL!,
    tokenURL: process.env.OAUTH_TOKEN_URL!,
    userInfoURL: process.env.OAUTH_USERINFO_URL!,
    scope: ['openid', 'profile', 'email'],
    callbackURL: process.env.OAUTH_CALLBACK_URL!,
  } : undefined,
  saml: process.env.SAML_ENTRY_POINT ? {
    entryPoint: process.env.SAML_ENTRY_POINT,
    issuer: process.env.SAML_ISSUER!,
    cert: process.env.SAML_CERT!,
    callbackUrl: process.env.SAML_CALLBACK_URL!,
  } : undefined,
});

const webauthnProvider = new WebAuthnProvider({
  rpName: 'AI Security Posture Management',
  rpID: process.env.WEBAUTHN_RP_ID || 'localhost',
  origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:5000',
});

const securityEngine = new SecurityEventCorrelationEngine();

// Configure Passport strategies
if (process.env.OAUTH_CLIENT_ID) {
  passport.use('oauth', authProvider.createOAuthStrategy());
}

if (process.env.SAML_ENTRY_POINT) {
  passport.use('saml', authProvider.createSAMLStrategy());
}

passport.use('jwt', authProvider.createJWTStrategy());

// OAuth 2.0/OpenID Connect Routes
router.get('/oauth/login', passport.authenticate('oauth'));

router.get('/oauth/callback', 
  passport.authenticate('oauth', { session: false }),
  (req, res) => {
    try {
      const user = req.user as any;
      const token = authProvider.generateJWT(user);
      
      // Log successful authentication
      securityEngine.ingestEvent({
        source: 'auth-service',
        type: 'authentication',
        severity: 'low',
        category: 'oauth_login',
        description: 'User authenticated via OAuth',
        actor: {
          userId: user.id,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        target: {
          resource: 'authentication',
          action: 'login',
        },
        metadata: {
          success: true,
          provider: 'oauth',
          correlationId: req.headers['x-correlation-id'],
        },
      });

      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
      });

      res.redirect('/dashboard');
    } catch (error) {
      console.error('OAuth callback error:', error);
      res.redirect('/auth?error=oauth_failed');
    }
  }
);

// SAML Routes
router.get('/saml/login', passport.authenticate('saml'));

router.post('/saml/callback',
  passport.authenticate('saml', { session: false }),
  (req, res) => {
    try {
      const user = req.user as any;
      const token = authProvider.generateJWT(user);
      
      // Log successful authentication
      securityEngine.ingestEvent({
        source: 'auth-service',
        type: 'authentication',
        severity: 'low',
        category: 'saml_login',
        description: 'User authenticated via SAML',
        actor: {
          userId: user.id,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        target: {
          resource: 'authentication',
          action: 'login',
        },
        metadata: {
          success: true,
          provider: 'saml',
          correlationId: req.headers['x-correlation-id'],
        },
      });

      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
      });

      res.json({ success: true, token });
    } catch (error) {
      console.error('SAML callback error:', error);
      res.status(400).json({ error: 'SAML authentication failed' });
    }
  }
);

// WebAuthn/FIDO2 Routes
router.post('/webauthn/register/begin', webauthnLimiter, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID required' });
    }

    // Get user from database (simplified)
    const user = { id: userId, email: `user${userId}@example.com`, name: `User ${userId}` };
    
    const options = webauthnProvider.generateRegistrationOptions(user);
    
    // Store challenge in session/database for verification
    req.session = req.session || {};
    req.session.challenge = options.challenge;
    req.session.userId = userId;

    res.json(options);
  } catch (error) {
    console.error('WebAuthn registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/webauthn/register/finish', webauthnLimiter, async (req, res) => {
  try {
    const { response } = req.body;
    const challenge = req.session?.challenge;
    const userId = req.session?.userId;

    if (!challenge || !userId) {
      return res.status(400).json({ error: 'Invalid session' });
    }

    const verification = await webauthnProvider.verifyRegistrationResponse(response, challenge);
    
    if (verification.verified) {
      // Store credential in database
      console.log('WebAuthn credential registered:', verification.credentialID);
      
      // Log successful registration
      securityEngine.ingestEvent({
        source: 'auth-service',
        type: 'authentication',
        severity: 'low',
        category: 'webauthn_register',
        description: 'User registered WebAuthn credential',
        actor: {
          userId,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        target: {
          resource: 'authentication',
          action: 'register_webauthn',
        },
        metadata: {
          success: true,
          credentialId: verification.credentialID,
        },
      });

      res.json({ verified: true });
    } else {
      res.status(400).json({ error: verification.error });
    }
  } catch (error) {
    console.error('WebAuthn registration verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

router.post('/webauthn/authenticate/begin', webauthnLimiter, async (req, res) => {
  try {
    const { userId } = req.body;
    
    // Get user's credentials from database (simplified)
    const allowCredentials = []; // Would fetch from database
    
    const options = webauthnProvider.generateAuthenticationOptions(allowCredentials);
    
    // Store challenge in session
    req.session = req.session || {};
    req.session.challenge = options.challenge;
    req.session.userId = userId;

    res.json(options);
  } catch (error) {
    console.error('WebAuthn authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

router.post('/webauthn/authenticate/finish', webauthnLimiter, async (req, res) => {
  try {
    const { response } = req.body;
    const challenge = req.session?.challenge;
    const userId = req.session?.userId;

    if (!challenge || !userId) {
      return res.status(400).json({ error: 'Invalid session' });
    }

    // Get saved credential from database (simplified)
    const savedCredential = { credentialID: response.id, counter: 0 };
    
    const verification = await webauthnProvider.verifyAuthenticationResponse(
      response, 
      challenge, 
      savedCredential
    );
    
    if (verification.verified) {
      const user = { id: userId, email: `user${userId}@example.com`, name: `User ${userId}` };
      const token = authProvider.generateJWT(user);
      
      // Log successful authentication
      securityEngine.ingestEvent({
        source: 'auth-service',
        type: 'authentication',
        severity: 'low',
        category: 'webauthn_login',
        description: 'User authenticated via WebAuthn',
        actor: {
          userId,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        target: {
          resource: 'authentication',
          action: 'login',
        },
        metadata: {
          success: true,
          provider: 'webauthn',
        },
      });

      res.json({ verified: true, token });
    } else {
      // Log failed authentication
      securityEngine.ingestEvent({
        source: 'auth-service',
        type: 'authentication',
        severity: 'medium',
        category: 'webauthn_login',
        description: 'WebAuthn authentication failed',
        actor: {
          userId,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        target: {
          resource: 'authentication',
          action: 'login',
        },
        metadata: {
          success: false,
          provider: 'webauthn',
          error: verification.error,
        },
      });

      res.status(400).json({ error: verification.error });
    }
  } catch (error) {
    console.error('WebAuthn authentication verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// API Key Management Routes
router.post('/api-keys', authLimiter, passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const { scopes, expiresIn } = req.body;
    const user = req.user as any;

    if (!user.permissions?.includes('api:manage')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const apiKey = authProvider.generateJWT(user, { expiresIn: expiresIn || '1y' });
    
    // Log API key creation
    securityEngine.ingestEvent({
      source: 'auth-service',
      type: 'authorization',
      severity: 'medium',
      category: 'api_key_created',
      description: 'API key created',
      actor: {
        userId: user.id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      target: {
        resource: 'api_key',
        action: 'create',
      },
      metadata: {
        scopes,
        expiresIn,
      },
    });

    res.json({
      apiKey,
      scopes,
      expiresIn,
      created: new Date().toISOString(),
    });
  } catch (error) {
    console.error('API key creation error:', error);
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

router.delete('/api-keys/:keyId', authLimiter, passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const { keyId } = req.params;
    const user = req.user as any;

    if (!user.permissions?.includes('api:manage')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    console.log('API_KEY_REVOKED:', { keyId, timestamp: new Date().toISOString() });
    
    // Log API key revocation
    securityEngine.ingestEvent({
      source: 'auth-service',
      type: 'authorization',
      severity: 'medium',
      category: 'api_key_revoked',
      description: 'API key revoked',
      actor: {
        userId: user.id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      target: {
        resource: 'api_key',
        resourceId: keyId,
        action: 'revoke',
      },
      metadata: {},
    });

    res.json({ success: true });
  } catch (error) {
    console.error('API key revocation error:', error);
    res.status(500).json({ error: 'Failed to revoke API key' });
  }
});

// Token refresh endpoint
router.post('/refresh', authLimiter, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    const newToken = authProvider.refreshJWT(refreshToken);
    
    res.json({ token: newToken });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout endpoint
router.post('/logout', (req, res) => {
  const user = req.user as any;
  
  // Clear cookie
  res.clearCookie('token');
  
  // Log logout
  if (user) {
    securityEngine.ingestEvent({
      source: 'auth-service',
      type: 'authentication',
      severity: 'low',
      category: 'logout',
      description: 'User logged out',
      actor: {
        userId: user.id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      target: {
        resource: 'authentication',
        action: 'logout',
      },
      metadata: {},
    });
  }

  res.json({ success: true });
});

export { router as authRoutes, securityEngine };