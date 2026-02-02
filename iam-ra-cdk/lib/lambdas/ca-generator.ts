/**
 * CA Generator Lambda Handler
 *
 * Generates a self-managed Certificate Authority for IAM Roles Anywhere.
 * Used as a CloudFormation custom resource via CDK Provider.
 *
 * This Lambda:
 * 1. Generates an EC P-256 CA key pair using Web Crypto API
 * 2. Creates a self-signed CA certificate using @peculiar/x509
 * 3. Returns CACertificate and CAPrivateKey via response Data
 *
 * The Provider construct handles the CloudFormation custom resource protocol.
 */

import * as crypto from 'node:crypto';
import * as x509 from '@peculiar/x509';
import type {
  CloudFormationCustomResourceEvent,
  CloudFormationCustomResourceResponse,
  CloudFormationCustomResourceUpdateEvent,
} from 'aws-lambda';

// Use Web Crypto API from Node.js
// eslint-disable-next-line @typescript-eslint/no-explicit-any
x509.cryptoProvider.set(crypto.webcrypto as any);

interface CaGeneratorProperties {
  ValidityYears?: string | number;
}

interface CaGeneratorResponse {
  CACertificate: string;
  CAPrivateKey: string;
}

/**
 * Generate a self-signed CA certificate and private key
 */
async function generateCaCertificate(validityYears: number): Promise<CaGeneratorResponse> {
  console.log(`Generating EC P-256 CA key pair with ${validityYears} year validity`);

  // Generate EC P-256 key pair
  const algorithm = {
    name: 'ECDSA',
    namedCurve: 'P-256',
  } as const;

  const keys = await crypto.webcrypto.subtle.generateKey(
    algorithm,
    true, // extractable
    ['sign', 'verify']
  );

  // Calculate validity dates
  const notBefore = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(notAfter.getFullYear() + validityYears);

  // Create self-signed CA certificate
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomBytes(16).toString('hex'),
    name: 'CN=Self-Managed CA, O=IAM Roles Anywhere, C=US',
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions: [
      // Basic Constraints: CA=true, pathLenConstraint=0
      new x509.BasicConstraintsExtension(true, 0, true),
      // Key Usage: keyCertSign, cRLSign, digitalSignature
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign |
        x509.KeyUsageFlags.cRLSign |
        x509.KeyUsageFlags.digitalSignature,
        true
      ),
      // Subject Key Identifier
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });

  // Export certificate to PEM
  const certPem = cert.toString('pem');

  // Export private key to PEM (PKCS#8 format)
  const privateKeyBuffer = await crypto.webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const privateKeyBase64 = Buffer.from(privateKeyBuffer).toString('base64');
  const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;

  console.log('CA certificate generated successfully');
  console.log(`Serial Number: ${cert.serialNumber}`);
  console.log(`Not Before: ${cert.notBefore}`);
  console.log(`Not After: ${cert.notAfter}`);

  return {
    CACertificate: certPem,
    CAPrivateKey: privateKeyPem,
  };
}

/**
 * Lambda handler for CA generation
 *
 * Handles CREATE, UPDATE, and DELETE events from CloudFormation.
 * The CDK Provider construct handles the response protocol.
 */
export async function handler(
  event: CloudFormationCustomResourceEvent
): Promise<CloudFormationCustomResourceResponse> {
  console.log('Received event:', JSON.stringify(event, null, 2));

  const requestType = event.RequestType;
  const properties = event.ResourceProperties as unknown as CaGeneratorProperties;

  // Get physical resource ID (only available for Update/Delete)
  const physicalResourceId =
    requestType === 'Create'
      ? 'ca-certificate-generated'
      : (event as CloudFormationCustomResourceUpdateEvent).PhysicalResourceId;

  try {
    switch (requestType) {
      case 'Create': {
        const validityYears = Number(properties.ValidityYears ?? 10);
        const result = await generateCaCertificate(validityYears);

        return {
          Status: 'SUCCESS',
          PhysicalResourceId: 'ca-certificate-generated',
          StackId: event.StackId,
          RequestId: event.RequestId,
          LogicalResourceId: event.LogicalResourceId,
          Data: result,
        };
      }

      case 'Update': {
        // For updates, regenerate CA if validity changed
        const updateEvent = event as CloudFormationCustomResourceUpdateEvent;
        const oldProperties = (updateEvent.OldResourceProperties ?? {}) as CaGeneratorProperties;
        const newValidity = Number(properties.ValidityYears ?? 10);
        const oldValidity = Number(oldProperties.ValidityYears ?? 10);

        if (newValidity !== oldValidity) {
          console.log(`ValidityYears changed from ${oldValidity} to ${newValidity}, regenerating CA`);
          console.warn('WARNING: Regenerating CA will invalidate all host certificates!');
          const result = await generateCaCertificate(newValidity);

          return {
            Status: 'SUCCESS',
            PhysicalResourceId: 'ca-certificate-generated',
            StackId: event.StackId,
            RequestId: event.RequestId,
            LogicalResourceId: event.LogicalResourceId,
            Data: result,
          };
        }

        // No changes, return existing resource
        console.log('No changes detected, skipping CA regeneration');
        return {
          Status: 'SUCCESS',
          PhysicalResourceId: physicalResourceId,
          StackId: event.StackId,
          RequestId: event.RequestId,
          LogicalResourceId: event.LogicalResourceId,
        };
      }

      case 'Delete': {
        // Nothing to delete - CloudFormation manages the secrets/parameters
        console.log('DELETE event - CloudFormation will manage resource deletion');
        return {
          Status: 'SUCCESS',
          PhysicalResourceId: physicalResourceId,
          StackId: event.StackId,
          RequestId: event.RequestId,
          LogicalResourceId: event.LogicalResourceId,
        };
      }

      default: {
        throw new Error(`Unknown request type: ${requestType}`);
      }
    }
  } catch (error) {
    console.error('Error:', error);
    return {
      Status: 'FAILED',
      Reason: error instanceof Error ? error.message : 'Unknown error',
      PhysicalResourceId: physicalResourceId ?? 'ca-generation-failed',
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
    };
  }
}
