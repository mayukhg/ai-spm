import { Request, Response } from 'express';
import crypto from 'crypto';
import { z } from 'zod';

// WebAuthn/FIDO2 Configuration
const WebAuthnConfigSchema = z.object({
  rpName: z.string().default('AI Security Posture Management Platform'),
  rpId: z.string().default('localhost'),
  origin: z.string().url().default('http://localhost:5000'),
  timeout: z.number().default(60000), // 60 seconds
  attestation: z.enum(['none', 'indirect', 'direct']).default('none'),
  userVerification: z.enum(['required', 'preferred', 'discouraged']).default('preferred'),
  authenticatorSelection: z.object({
    authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
    requireResidentKey: z.boolean().default(false),
    userVerification: z.enum(['required', 'preferred', 'discouraged']).default('preferred')
  }).optional()
});

type WebAuthnConfig = z.infer<typeof WebAuthnConfigSchema>;

// WebAuthn Types
interface PublicKeyCredentialCreationOptions {
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  challenge: string;
  pubKeyCredParams: Array<{
    type: 'public-key';
    alg: number;
  }>;
  timeout?: number;
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: string[];
  }>;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  attestation?: string;
}

interface PublicKeyCredentialRequestOptions {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: string[];
  }>;
  userVerification?: string;
}

interface AuthenticatorAttestationResponse {
  clientDataJSON: string;
  attestationObject: string;
  transports?: string[];
}

interface AuthenticatorAssertionResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

interface StoredCredential {
  credentialId: string;
  credentialPublicKey: string;
  counter: number;
  userId: string;
  transports?: string[];
  created: Date;
  lastUsed: Date;
}

export class WebAuthnProvider {
  private config: WebAuthnConfig;
  private challenges: Map<string, { challenge: string; userId: string; timestamp: number }> = new Map();
  private credentials: Map<string, StoredCredential> = new Map(); // In production, use database
  private readonly challengeExpiry = 5 * 60 * 1000; // 5 minutes

  constructor(config: Partial<WebAuthnConfig> = {}) {
    this.config = WebAuthnConfigSchema.parse(config);
    this.cleanupExpiredChallenges();
  }

  // Generate registration options
  generateRegistrationOptions(userId: string, userName: string, displayName: string): {
    options: PublicKeyCredentialCreationOptions;
    challenge: string;
  } {
    const challenge = crypto.randomBytes(32).toString('base64url');
    
    // Store challenge
    this.challenges.set(challenge, {
      challenge,
      userId,
      timestamp: Date.now()
    });

    // Get existing credentials to exclude
    const existingCredentials = Array.from(this.credentials.values())
      .filter(cred => cred.userId === userId)
      .map(cred => ({
        id: cred.credentialId,
        type: 'public-key' as const,
        transports: cred.transports as AuthenticatorTransport[]
      }));

    const options: PublicKeyCredentialCreationOptions = {
      rp: {
        name: this.config.rpName,
        id: this.config.rpId
      },
      user: {
        id: userId,
        name: userName,
        displayName: displayName
      },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -35 }, // ES384
        { type: 'public-key', alg: -36 }, // ES512
        { type: 'public-key', alg: -257 }, // RS256
        { type: 'public-key', alg: -258 }, // RS384
        { type: 'public-key', alg: -259 }, // RS512
        { type: 'public-key', alg: -37 }, // PS256
        { type: 'public-key', alg: -38 }, // PS384
        { type: 'public-key', alg: -39 }, // PS512
      ],
      timeout: this.config.timeout,
      excludeCredentials: existingCredentials,
      authenticatorSelection: this.config.authenticatorSelection,
      attestation: this.config.attestation
    };

    return { options, challenge };
  }

  // Generate authentication options
  generateAuthenticationOptions(userId?: string): {
    options: PublicKeyCredentialRequestOptions;
    challenge: string;
  } {
    const challenge = crypto.randomBytes(32).toString('base64url');
    
    // Store challenge
    this.challenges.set(challenge, {
      challenge,
      userId: userId || 'anonymous',
      timestamp: Date.now()
    });

    // Get user's credentials if userId provided
    const allowCredentials = userId 
      ? Array.from(this.credentials.values())
          .filter(cred => cred.userId === userId)
          .map(cred => ({
            id: cred.credentialId,
            type: 'public-key' as const,
            transports: cred.transports as AuthenticatorTransport[]
          }))
      : undefined;

    const options: PublicKeyCredentialRequestOptions = {
      challenge,
      timeout: this.config.timeout,
      rpId: this.config.rpId,
      allowCredentials,
      userVerification: this.config.userVerification
    };

    return { options, challenge };
  }

  // Verify registration response
  async verifyRegistrationResponse(
    response: {
      id: string;
      rawId: string;
      response: AuthenticatorAttestationResponse;
      type: string;
    },
    expectedChallenge: string,
    userId: string
  ): Promise<{ verified: boolean; credentialId?: string; credentialPublicKey?: string }> {
    try {
      // Verify challenge
      const challengeData = this.challenges.get(expectedChallenge);
      if (!challengeData || challengeData.userId !== userId) {
        throw new Error('Invalid challenge');
      }
      
      if (Date.now() - challengeData.timestamp > this.challengeExpiry) {
        throw new Error('Challenge expired');
      }

      // Clean up challenge
      this.challenges.delete(expectedChallenge);

      // Decode client data
      const clientDataJSON = JSON.parse(
        Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8')
      );

      // Verify client data
      if (clientDataJSON.type !== 'webauthn.create') {
        throw new Error('Invalid client data type');
      }

      if (clientDataJSON.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch');
      }

      if (clientDataJSON.origin !== this.config.origin) {
        throw new Error('Origin mismatch');
      }

      // Decode attestation object
      const attestationObject = this.decodeAttestationObject(response.response.attestationObject);
      
      // Verify RP ID hash
      const rpIdHash = crypto.createHash('sha256').update(this.config.rpId).digest();
      if (!rpIdHash.equals(attestationObject.authData.rpIdHash)) {
        throw new Error('RP ID hash mismatch');
      }

      // Verify user present flag
      if (!(attestationObject.authData.flags & 0x01)) {
        throw new Error('User not present');
      }

      // Extract credential data
      const credentialId = response.id;
      const credentialPublicKey = this.extractPublicKey(attestationObject.authData);

      // Store credential
      const credential: StoredCredential = {
        credentialId,
        credentialPublicKey,
        counter: attestationObject.authData.counter,
        userId,
        transports: response.response.transports,
        created: new Date(),
        lastUsed: new Date()
      };

      this.credentials.set(credentialId, credential);

      return {
        verified: true,
        credentialId,
        credentialPublicKey
      };

    } catch (error) {
      console.error('WebAuthn registration verification failed:', error);
      return { verified: false };
    }
  }

  // Verify authentication response
  async verifyAuthenticationResponse(
    response: {
      id: string;
      rawId: string;
      response: AuthenticatorAssertionResponse;
      type: string;
    },
    expectedChallenge: string
  ): Promise<{ verified: boolean; userId?: string; credentialId?: string }> {
    try {
      // Verify challenge
      const challengeData = this.challenges.get(expectedChallenge);
      if (!challengeData) {
        throw new Error('Invalid challenge');
      }
      
      if (Date.now() - challengeData.timestamp > this.challengeExpiry) {
        throw new Error('Challenge expired');
      }

      // Clean up challenge
      this.challenges.delete(expectedChallenge);

      // Get stored credential
      const credential = this.credentials.get(response.id);
      if (!credential) {
        throw new Error('Credential not found');
      }

      // Decode client data
      const clientDataJSON = JSON.parse(
        Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8')
      );

      // Verify client data
      if (clientDataJSON.type !== 'webauthn.get') {
        throw new Error('Invalid client data type');
      }

      if (clientDataJSON.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch');
      }

      if (clientDataJSON.origin !== this.config.origin) {
        throw new Error('Origin mismatch');
      }

      // Decode authenticator data
      const authenticatorData = Buffer.from(response.response.authenticatorData, 'base64url');
      const authData = this.parseAuthenticatorData(authenticatorData);

      // Verify RP ID hash
      const rpIdHash = crypto.createHash('sha256').update(this.config.rpId).digest();
      if (!rpIdHash.equals(authData.rpIdHash)) {
        throw new Error('RP ID hash mismatch');
      }

      // Verify user present flag
      if (!(authData.flags & 0x01)) {
        throw new Error('User not present');
      }

      // Verify counter (replay attack protection)
      if (authData.counter !== 0 && authData.counter <= credential.counter) {
        throw new Error('Invalid counter value');
      }

      // Verify signature
      const clientDataHash = crypto.createHash('sha256')
        .update(Buffer.from(response.response.clientDataJSON, 'base64url'))
        .digest();
      
      const signedData = Buffer.concat([authenticatorData, clientDataHash]);
      const signature = Buffer.from(response.response.signature, 'base64url');
      
      const verified = this.verifySignature(
        signedData,
        signature,
        credential.credentialPublicKey
      );

      if (!verified) {
        throw new Error('Signature verification failed');
      }

      // Update counter and last used
      credential.counter = authData.counter;
      credential.lastUsed = new Date();
      this.credentials.set(response.id, credential);

      return {
        verified: true,
        userId: credential.userId,
        credentialId: response.id
      };

    } catch (error) {
      console.error('WebAuthn authentication verification failed:', error);
      return { verified: false };
    }
  }

  // Get user credentials
  getUserCredentials(userId: string): StoredCredential[] {
    return Array.from(this.credentials.values())
      .filter(cred => cred.userId === userId);
  }

  // Remove credential
  removeCredential(credentialId: string, userId: string): boolean {
    const credential = this.credentials.get(credentialId);
    if (credential && credential.userId === userId) {
      this.credentials.delete(credentialId);
      return true;
    }
    return false;
  }

  // Helper: Decode attestation object
  private decodeAttestationObject(attestationObject: string): any {
    // This is a simplified CBOR decoder
    // In production, use a proper CBOR library
    const buffer = Buffer.from(attestationObject, 'base64url');
    
    // Parse authenticator data (simplified)
    const authData = this.parseAuthenticatorData(buffer.slice(37)); // Skip CBOR headers
    
    return {
      authData,
      fmt: 'none', // Simplified
      attStmt: {}
    };
  }

  // Helper: Parse authenticator data
  private parseAuthenticatorData(authData: Buffer): any {
    if (authData.length < 37) {
      throw new Error('Invalid authenticator data length');
    }

    return {
      rpIdHash: authData.slice(0, 32),
      flags: authData[32],
      counter: authData.readUInt32BE(33)
    };
  }

  // Helper: Extract public key from authenticator data
  private extractPublicKey(authData: any): string {
    // This is a placeholder - implement proper COSE key extraction
    return 'placeholder-public-key';
  }

  // Helper: Verify signature
  private verifySignature(data: Buffer, signature: Buffer, publicKey: string): boolean {
    // This is a placeholder - implement proper signature verification
    // based on the algorithm used in the public key
    return true;
  }

  // Cleanup expired challenges
  private cleanupExpiredChallenges(): void {
    setInterval(() => {
      const now = Date.now();
      for (const [challenge, data] of this.challenges.entries()) {
        if (now - data.timestamp > this.challengeExpiry) {
          this.challenges.delete(challenge);
        }
      }
    }, 2 * 60 * 1000); // Cleanup every 2 minutes
  }
}