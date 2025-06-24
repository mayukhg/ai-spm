import { Request, Response } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { parseString as parseXML } from 'xml2js';
import { promisify } from 'util';

const parseXMLAsync = promisify(parseXML);

// SAML Configuration Schema
const SAMLConfigSchema = z.object({
  entityId: z.string(),
  ssoUrl: z.string().url(),
  sloUrl: z.string().url().optional(),
  certificate: z.string(), // Base64 encoded certificate
  privateKey: z.string().optional(), // For signing requests
  signRequests: z.boolean().default(false),
  wantAssertionsSigned: z.boolean().default(true),
  nameIDFormat: z.string().default('urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'),
  attributeMapping: z.object({
    email: z.string().default('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'),
    firstName: z.string().default('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'),
    lastName: z.string().default('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'),
    groups: z.string().default('http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'),
    role: z.string().default('http://schemas.microsoft.com/ws/2008/06/identity/claims/role')
  }).optional()
});

type SAMLConfig = z.infer<typeof SAMLConfigSchema>;

interface SAMLAssertion {
  nameId: string;
  sessionIndex?: string;
  attributes: Record<string, string | string[]>;
  conditions?: {
    notBefore?: Date;
    notOnOrAfter?: Date;
    audienceRestrictions?: string[];
  };
}

export class SAMLProvider {
  private config: SAMLConfig;
  private pendingRequests: Map<string, { timestamp: number; relayState?: string }> = new Map();
  private readonly requestExpiry = 10 * 60 * 1000; // 10 minutes

  constructor(config: SAMLConfig) {
    this.config = SAMLConfigSchema.parse(config);
    this.cleanupExpiredRequests();
  }

  // Generate SAML Authentication Request
  generateAuthRequest(req: Request): { xml: string; id: string; relayState?: string } {
    const id = '_' + crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const relayState = req.query.RelayState as string;

    // Store request ID
    this.pendingRequests.set(id, {
      timestamp: Date.now(),
      relayState
    });

    const authRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${id}"
    Version="2.0"
    IssueInstant="${timestamp}"
    Destination="${this.config.ssoUrl}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="${process.env.BASE_URL || 'http://localhost:5000'}/auth/saml/callback">
    <saml:Issuer>${this.config.entityId}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="${this.config.nameIDFormat}"
        AllowCreate="true"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

    let signedRequest = authRequest;

    // Sign request if configured
    if (this.config.signRequests && this.config.privateKey) {
      signedRequest = this.signXML(authRequest, this.config.privateKey);
    }

    return {
      xml: signedRequest,
      id,
      relayState
    };
  }

  // Generate logout request
  generateLogoutRequest(nameId: string, sessionIndex?: string): string {
    const id = '_' + crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const logoutRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${id}"
    Version="2.0"
    IssueInstant="${timestamp}"
    Destination="${this.config.sloUrl}">
    <saml:Issuer>${this.config.entityId}</saml:Issuer>
    <saml:NameID Format="${this.config.nameIDFormat}">${nameId}</saml:NameID>
    ${sessionIndex ? `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex>` : ''}
</samlp:LogoutRequest>`;

    if (this.config.signRequests && this.config.privateKey) {
      return this.signXML(logoutRequest, this.config.privateKey);
    }

    return logoutRequest;
  }

  // Process SAML Response
  async processSAMLResponse(samlResponse: string, relayState?: string): Promise<SAMLAssertion> {
    try {
      // Decode base64 response
      const decodedResponse = Buffer.from(samlResponse, 'base64').toString('utf8');
      
      // Parse XML
      const parsed = await parseXMLAsync(decodedResponse, { 
        explicitArray: false,
        ignoreAttrs: false
      });

      const response = parsed['samlp:Response'] || parsed.Response;
      
      if (!response) {
        throw new Error('Invalid SAML response format');
      }

      // Check response status
      const status = response['samlp:Status'] || response.Status;
      const statusCode = status['samlp:StatusCode'] || status.StatusCode;
      
      if (statusCode.$.Value !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        throw new Error(`SAML authentication failed: ${statusCode.$.Value}`);
      }

      // Verify signature if required
      if (this.config.wantAssertionsSigned) {
        this.verifySignature(decodedResponse, this.config.certificate);
      }

      // Extract assertion
      const assertion = response['saml:Assertion'] || response.Assertion;
      
      if (!assertion) {
        throw new Error('No assertion found in SAML response');
      }

      // Validate conditions
      this.validateConditions(assertion);

      // Extract user information
      const nameId = assertion['saml:Subject']['saml:NameID']._ || 
                    assertion.Subject.NameID._ ||
                    assertion.Subject.NameID;

      const sessionIndex = assertion['saml:AuthnStatement']?.$?.SessionIndex ||
                          assertion.AuthnStatement?.$.SessionIndex;

      // Extract attributes
      const attributes = this.extractAttributes(assertion);

      return {
        nameId,
        sessionIndex,
        attributes
      };

    } catch (error) {
      throw new Error(`SAML response processing failed: ${error}`);
    }
  }

  // Extract attributes from assertion
  private extractAttributes(assertion: any): Record<string, string | string[]> {
    const attributes: Record<string, string | string[]> = {};
    
    const attributeStatement = assertion['saml:AttributeStatement'] || assertion.AttributeStatement;
    
    if (!attributeStatement) {
      return attributes;
    }

    const attributeList = Array.isArray(attributeStatement) ? attributeStatement : [attributeStatement];
    
    attributeList.forEach((statement: any) => {
      const attrs = statement['saml:Attribute'] || statement.Attribute;
      
      if (!attrs) return;
      
      const attrArray = Array.isArray(attrs) ? attrs : [attrs];
      
      attrArray.forEach((attr: any) => {
        const name = attr.$.Name || attr.$.FriendlyName;
        const values = attr['saml:AttributeValue'] || attr.AttributeValue;
        
        if (name && values) {
          if (Array.isArray(values)) {
            attributes[name] = values.map((v: any) => v._ || v);
          } else {
            attributes[name] = values._ || values;
          }
        }
      });
    });

    return attributes;
  }

  // Validate assertion conditions
  private validateConditions(assertion: any): void {
    const conditions = assertion['saml:Conditions'] || assertion.Conditions;
    
    if (!conditions) return;

    // Check time bounds
    const now = new Date();
    
    if (conditions.$.NotBefore) {
      const notBefore = new Date(conditions.$.NotBefore);
      if (now < notBefore) {
        throw new Error('SAML assertion not yet valid');
      }
    }

    if (conditions.$.NotOnOrAfter) {
      const notOnOrAfter = new Date(conditions.$.NotOnOrAfter);
      if (now >= notOnOrAfter) {
        throw new Error('SAML assertion has expired');
      }
    }

    // Check audience restrictions
    const audienceRestriction = conditions['saml:AudienceRestriction'] || conditions.AudienceRestriction;
    
    if (audienceRestriction) {
      const audiences = audienceRestriction['saml:Audience'] || audienceRestriction.Audience;
      const audienceList = Array.isArray(audiences) ? audiences : [audiences];
      
      const validAudience = audienceList.some((audience: any) => {
        const audienceValue = audience._ || audience;
        return audienceValue === this.config.entityId;
      });

      if (!validAudience) {
        throw new Error('SAML assertion audience restriction failed');
      }
    }
  }

  // Verify XML signature
  private verifySignature(xml: string, certificate: string): void {
    try {
      // This is a simplified signature verification
      // In production, use a proper XML signature library like xml-crypto
      const cert = certificate.replace(/-----BEGIN CERTIFICATE-----|\-----END CERTIFICATE-----|\n|\r/g, '');
      const publicKey = crypto.createPublicKey({
        key: `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`,
        format: 'pem'
      });

      // Extract signature value from XML (simplified)
      const signatureMatch = xml.match(/<ds:SignatureValue[^>]*>([^<]+)<\/ds:SignatureValue>/);
      
      if (!signatureMatch) {
        throw new Error('No signature found in SAML response');
      }

      // In a real implementation, you would:
      // 1. Canonicalize the signed element
      // 2. Calculate the digest
      // 3. Verify the signature
      
      console.log('SAML signature verification placeholder - implement with xml-crypto');
      
    } catch (error) {
      throw new Error(`SAML signature verification failed: ${error}`);
    }
  }

  // Sign XML (simplified)
  private signXML(xml: string, privateKey: string): string {
    // This is a placeholder for XML signing
    // In production, use xml-crypto library for proper XML signing
    console.log('SAML XML signing placeholder - implement with xml-crypto');
    return xml;
  }

  // Map SAML attributes to user profile
  mapAttributesToProfile(attributes: Record<string, string | string[]>): {
    email: string;
    name: string;
    firstName?: string;
    lastName?: string;
    groups?: string[];
    roles?: string[];
  } {
    const mapping = this.config.attributeMapping || {};
    
    const email = (attributes[mapping.email || 'email'] as string) || '';
    const firstName = (attributes[mapping.firstName || 'firstName'] as string) || '';
    const lastName = (attributes[mapping.lastName || 'lastName'] as string) || '';
    const groups = Array.isArray(attributes[mapping.groups || 'groups']) 
      ? attributes[mapping.groups || 'groups'] as string[]
      : typeof attributes[mapping.groups || 'groups'] === 'string'
      ? [attributes[mapping.groups || 'groups'] as string]
      : [];
    
    const roles = Array.isArray(attributes[mapping.role || 'role'])
      ? attributes[mapping.role || 'role'] as string[]
      : typeof attributes[mapping.role || 'role'] === 'string'
      ? [attributes[mapping.role || 'role'] as string]
      : [];

    return {
      email,
      name: firstName && lastName ? `${firstName} ${lastName}` : firstName || lastName || email,
      firstName,
      lastName,
      groups,
      roles
    };
  }

  // Generate Service Provider Metadata
  generateMetadata(): string {
    const entityId = this.config.entityId;
    const baseUrl = process.env.BASE_URL || 'http://localhost:5000';
    
    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="${entityId}">
    <md:SPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
        WantAssertionsSigned="${this.config.wantAssertionsSigned}">
        <md:NameIDFormat>${this.config.nameIDFormat}</md:NameIDFormat>
        <md:AssertionConsumerService
            index="0"
            isDefault="true"
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="${baseUrl}/auth/saml/callback"/>
        ${this.config.sloUrl ? `
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="${baseUrl}/auth/saml/logout"/>
        ` : ''}
    </md:SPSSODescriptor>
</md:EntityDescriptor>`;
  }

  // Cleanup expired requests
  private cleanupExpiredRequests(): void {
    setInterval(() => {
      const now = Date.now();
      for (const [id, data] of this.pendingRequests.entries()) {
        if (now - data.timestamp > this.requestExpiry) {
          this.pendingRequests.delete(id);
        }
      }
    }, 5 * 60 * 1000); // Cleanup every 5 minutes
  }
}