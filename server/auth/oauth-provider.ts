import { Strategy as OAuthStrategy } from 'passport-oauth2';
import { Strategy as SamlStrategy } from 'passport-saml';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Request } from 'express';

export interface OAuthConfig {
  clientID: string;
  clientSecret: string;
  authorizationURL: string;
  tokenURL: string;
  userInfoURL: string;
  scope: string[];
  callbackURL: string;
}

export interface SAMLConfig {
  entryPoint: string;
  issuer: string;
  cert: string;
  callbackUrl: string;
  identifierFormat?: string;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
}

export interface JWTConfig {
  secret: string;
  issuer: string;
  audience: string;
  algorithm: string;
  expiresIn: string;
}

export class AuthenticationProvider {
  private jwtConfig: JWTConfig;
  private oauthConfig?: OAuthConfig;
  private samlConfig?: SAMLConfig;

  constructor(configs: {
    jwt: JWTConfig;
    oauth?: OAuthConfig;
    saml?: SAMLConfig;
  }) {
    this.jwtConfig = configs.jwt;
    this.oauthConfig = configs.oauth;
    this.samlConfig = configs.saml;
  }

  // OAuth 2.0/OpenID Connect Strategy
  createOAuthStrategy() {
    if (!this.oauthConfig) {
      throw new Error('OAuth configuration not provided');
    }

    return new OAuthStrategy(
      {
        authorizationURL: this.oauthConfig.authorizationURL,
        tokenURL: this.oauthConfig.tokenURL,
        clientID: this.oauthConfig.clientID,
        clientSecret: this.oauthConfig.clientSecret,
        callbackURL: this.oauthConfig.callbackURL,
        scope: this.oauthConfig.scope,
      },
      async (accessToken: string, refreshToken: string, profile: any, done: Function) => {
        try {
          // Fetch user info from OAuth provider
          const userInfo = await this.fetchUserInfo(accessToken);
          
          // Map OAuth user to internal user structure
          const user = {
            id: userInfo.sub || userInfo.id,
            email: userInfo.email,
            name: userInfo.name || `${userInfo.given_name} ${userInfo.family_name}`,
            role: this.mapOAuthRole(userInfo.roles || userInfo.groups || []),
            provider: 'oauth',
            externalId: userInfo.sub || userInfo.id,
            accessToken,
            refreshToken,
            tokenExpiry: new Date(Date.now() + 3600000), // 1 hour
          };

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    );
  }

  // SAML Strategy
  createSAMLStrategy() {
    if (!this.samlConfig) {
      throw new Error('SAML configuration not provided');
    }

    return new SamlStrategy(
      {
        entryPoint: this.samlConfig.entryPoint,
        issuer: this.samlConfig.issuer,
        cert: this.samlConfig.cert,
        callbackUrl: this.samlConfig.callbackUrl,
        identifierFormat: this.samlConfig.identifierFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        signatureAlgorithm: this.samlConfig.signatureAlgorithm || 'sha256',
        digestAlgorithm: this.samlConfig.digestAlgorithm || 'sha256',
      },
      async (profile: any, done: Function) => {
        try {
          const user = {
            id: profile.nameID,
            email: profile.email || profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
            name: profile.name || profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'],
            role: this.mapSAMLRole(profile.role || profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] || []),
            provider: 'saml',
            externalId: profile.nameID,
            attributes: profile,
          };

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    );
  }

  // JWT Strategy for API authentication
  createJWTStrategy() {
    return new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromExtractors([
          ExtractJwt.fromAuthHeaderAsBearerToken(),
          ExtractJwt.fromHeader('x-api-token'),
          (req: Request) => req.cookies?.token,
        ]),
        secretOrKey: this.jwtConfig.secret,
        issuer: this.jwtConfig.issuer,
        audience: this.jwtConfig.audience,
        algorithms: [this.jwtConfig.algorithm as any],
      },
      async (payload: any, done: Function) => {
        try {
          // Validate JWT payload
          if (!payload.sub || !payload.email) {
            return done(null, false, { message: 'Invalid token payload' });
          }

          // Check if token is not expired
          if (payload.exp && Date.now() >= payload.exp * 1000) {
            return done(null, false, { message: 'Token expired' });
          }

          const user = {
            id: payload.sub,
            email: payload.email,
            name: payload.name,
            role: payload.role,
            permissions: payload.permissions || [],
            provider: 'jwt',
            sessionId: payload.sessionId,
          };

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    );
  }

  // Generate JWT token
  generateJWT(user: any, options: Partial<JWTConfig> = {}) {
    const payload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      permissions: user.permissions || [],
      sessionId: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
    };

    return jwt.sign(payload, this.jwtConfig.secret, {
      issuer: options.issuer || this.jwtConfig.issuer,
      audience: options.audience || this.jwtConfig.audience,
      algorithm: (options.algorithm || this.jwtConfig.algorithm) as any,
      expiresIn: options.expiresIn || this.jwtConfig.expiresIn,
    });
  }

  // Refresh JWT token
  refreshJWT(refreshToken: string) {
    try {
      const decoded = jwt.verify(refreshToken, this.jwtConfig.secret) as any;
      
      // Generate new access token
      return this.generateJWT(decoded);
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  // Fetch user info from OAuth provider
  private async fetchUserInfo(accessToken: string): Promise<any> {
    if (!this.oauthConfig?.userInfoURL) {
      throw new Error('User info URL not configured');
    }

    const response = await fetch(this.oauthConfig.userInfoURL, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user info: ${response.statusText}`);
    }

    return response.json();
  }

  // Map OAuth roles to internal roles
  private mapOAuthRole(externalRoles: string[]): string {
    const roleMapping = {
      'admin': 'ciso',
      'security-admin': 'ciso',
      'security-analyst': 'security-analyst',
      'ai-engineer': 'ai-engineer',
      'compliance-officer': 'compliance-officer',
      'auditor': 'compliance-officer',
    };

    for (const role of externalRoles) {
      const mappedRole = roleMapping[role.toLowerCase() as keyof typeof roleMapping];
      if (mappedRole) {
        return mappedRole;
      }
    }

    return 'security-analyst'; // default role
  }

  // Map SAML roles to internal roles
  private mapSAMLRole(externalRoles: string | string[]): string {
    const roles = Array.isArray(externalRoles) ? externalRoles : [externalRoles];
    return this.mapOAuthRole(roles);
  }

  // Validate service mesh JWT
  validateServiceMeshToken(token: string): boolean {
    try {
      const decoded = jwt.verify(token, this.jwtConfig.secret) as any;
      return decoded.type === 'service-mesh' && decoded.iss === 'istio-system';
    } catch {
      return false;
    }
  }
}

// WebAuthn/FIDO2 Support
export class WebAuthnProvider {
  private rpName: string;
  private rpID: string;
  private origin: string;

  constructor(config: { rpName: string; rpID: string; origin: string }) {
    this.rpName = config.rpName;
    this.rpID = config.rpID;
    this.origin = config.origin;
  }

  // Generate registration options
  generateRegistrationOptions(user: any) {
    const challenge = crypto.randomBytes(32);
    
    return {
      challenge: challenge.toString('base64url'),
      rp: {
        name: this.rpName,
        id: this.rpID,
      },
      user: {
        id: Buffer.from(user.id).toString('base64url'),
        name: user.email,
        displayName: user.name,
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' }, // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'required',
      },
      timeout: 60000,
      attestation: 'direct',
    };
  }

  // Generate authentication options
  generateAuthenticationOptions(allowCredentials: any[] = []) {
    const challenge = crypto.randomBytes(32);
    
    return {
      challenge: challenge.toString('base64url'),
      timeout: 60000,
      rpId: this.rpID,
      allowCredentials: allowCredentials.map(cred => ({
        id: cred.credentialID,
        type: 'public-key',
        transports: cred.transports || ['internal'],
      })),
      userVerification: 'required',
    };
  }

  // Verify registration response
  async verifyRegistrationResponse(response: any, expectedChallenge: string) {
    // This would typically use a WebAuthn library like @simplewebauthn/server
    // For now, we'll implement basic validation
    
    try {
      const { id, rawId, response: authResponse, type } = response;
      
      if (type !== 'public-key') {
        throw new Error('Invalid credential type');
      }

      // Verify challenge (simplified)
      const clientDataJSON = JSON.parse(
        Buffer.from(authResponse.clientDataJSON, 'base64').toString()
      );
      
      if (clientDataJSON.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch');
      }

      if (clientDataJSON.origin !== this.origin) {
        throw new Error('Origin mismatch');
      }

      return {
        verified: true,
        credentialID: id,
        credentialPublicKey: authResponse.attestationObject,
        counter: 0,
      };
    } catch (error) {
      return {
        verified: false,
        error: error instanceof Error ? error.message : 'Verification failed',
      };
    }
  }

  // Verify authentication response
  async verifyAuthenticationResponse(response: any, expectedChallenge: string, savedCredential: any) {
    try {
      const { id, rawId, response: authResponse, type } = response;
      
      if (type !== 'public-key') {
        throw new Error('Invalid credential type');
      }

      // Verify challenge
      const clientDataJSON = JSON.parse(
        Buffer.from(authResponse.clientDataJSON, 'base64').toString()
      );
      
      if (clientDataJSON.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch');
      }

      if (clientDataJSON.origin !== this.origin) {
        throw new Error('Origin mismatch');
      }

      // Verify credential ID matches
      if (id !== savedCredential.credentialID) {
        throw new Error('Credential ID mismatch');
      }

      return {
        verified: true,
        newCounter: savedCredential.counter + 1,
      };
    } catch (error) {
      return {
        verified: false,
        error: error instanceof Error ? error.message : 'Authentication failed',
      };
    }
  }
}