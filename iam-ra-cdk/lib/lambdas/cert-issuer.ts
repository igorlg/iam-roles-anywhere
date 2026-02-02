/**
 * Certificate Issuer Lambda Handler
 *
 * Issues host certificates for IAM Roles Anywhere.
 * Used as a CloudFormation custom resource via CDK Provider.
 *
 * Supports CA modes:
 * 1. self-managed: Signs certificates using CA key from Secrets Manager
 * 2. pca-existing/pca-managed: Issues certificates via ACM Private CA
 *
 * This Lambda:
 * 1. Generates an EC P-256 host key pair
 * 2. Creates a CSR with CN=hostname
 * 3. Signs certificate (self-managed) or issues via PCA
 * 4. Returns Certificate and PrivateKey via response Data
 */

import * as crypto from 'node:crypto';
import * as x509 from '@peculiar/x509';
import {
  ACMPCAClient,
  DescribeCertificateAuthorityCommand,
  IssueCertificateCommand,
  GetCertificateCommand,
  waitUntilCertificateIssued,
  SigningAlgorithm,
} from '@aws-sdk/client-acm-pca';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import type {
  CloudFormationCustomResourceEvent,
  CloudFormationCustomResourceResponse,
  CloudFormationCustomResourceUpdateEvent,
} from 'aws-lambda';

// Use Web Crypto API from Node.js
// eslint-disable-next-line @typescript-eslint/no-explicit-any
x509.cryptoProvider.set(crypto.webcrypto as any);

// AWS SDK clients
const acmPcaClient = new ACMPCAClient({});
const secretsClient = new SecretsManagerClient({});

interface CertIssuerProperties {
  Hostname: string;
  CAMode: 'self-managed' | 'pca-existing' | 'pca-managed';
  ValidityDays?: string | number;
  // Self-managed mode properties
  CAPrivateKeySecretArn?: string;
  CACertificatePem?: string;
  // PCA mode properties
  PCAArn?: string;
}

interface CertIssuerResponse {
  Certificate: string;
  PrivateKey: string;
  Hostname: string;
}

/**
 * Generate EC P-256 key pair and CSR for a host
 */
async function generateHostKeyAndCsr(hostname: string): Promise<{
  privateKeyPem: string;
  csrPem: string;
  publicKey: crypto.webcrypto.CryptoKey;
}> {
  console.log(`Generating EC P-256 key pair for hostname: ${hostname}`);

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

  // Create CSR
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${hostname}`,
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });

  // Export private key to PEM (PKCS#8 format)
  const privateKeyBuffer = await crypto.webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const privateKeyBase64 = Buffer.from(privateKeyBuffer).toString('base64');
  const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;

  // Export CSR to PEM
  const csrPem = csr.toString('pem');

  console.log(`Generated key and CSR for: ${hostname}`);

  return {
    privateKeyPem,
    csrPem,
    publicKey: keys.publicKey,
  };
}

/**
 * Sign a certificate using the self-managed CA
 */
async function signCertificateSelfManaged(
  hostname: string,
  publicKey: crypto.webcrypto.CryptoKey,
  caPrivateKeySecretArn: string,
  caCertificatePem: string,
  validityDays: number
): Promise<string> {
  console.log(`Signing certificate for ${hostname} using self-managed CA`);

  if (!caPrivateKeySecretArn) {
    throw new Error('CA private key secret ARN not provided');
  }
  if (!caCertificatePem) {
    throw new Error('CA certificate PEM not provided');
  }

  // Fetch CA private key from Secrets Manager
  const secretResponse = await secretsClient.send(
    new GetSecretValueCommand({ SecretId: caPrivateKeySecretArn })
  );
  const caPrivateKeyPem = secretResponse.SecretString;
  if (!caPrivateKeyPem) {
    throw new Error('CA private key secret is empty');
  }

  // Parse CA certificate
  const caCert = new x509.X509Certificate(caCertificatePem);

  // Import CA private key
  const caPrivateKeyDer = Buffer.from(
    caPrivateKeyPem
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, ''),
    'base64'
  );
  const caPrivateKey = await crypto.webcrypto.subtle.importKey(
    'pkcs8',
    caPrivateKeyDer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  // Calculate validity dates
  const notBefore = new Date();
  const notAfter = new Date();
  notAfter.setDate(notAfter.getDate() + validityDays);

  // Create and sign certificate
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(16).toString('hex'),
    subject: `CN=${hostname}`,
    issuer: caCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signingKey: caPrivateKey,
    extensions: [
      // Basic Constraints: CA=false
      new x509.BasicConstraintsExtension(false, undefined, true),
      // Key Usage: digitalSignature only
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      // Extended Key Usage: clientAuth (required for IAM Roles Anywhere)
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.2'], false), // clientAuth OID
      // Subject Key Identifier
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
    ],
  });

  const certPem = cert.toString('pem');

  console.log(`Certificate signed for ${hostname}`);
  console.log(`Serial Number: ${cert.serialNumber}`);
  console.log(`Not Before: ${cert.notBefore}`);
  console.log(`Not After: ${cert.notAfter}`);

  return certPem;
}

/**
 * Get the appropriate signing algorithm for a PCA based on its key type
 */
async function getPcaSigningAlgorithm(pcaArn: string): Promise<SigningAlgorithm> {
  const response = await acmPcaClient.send(
    new DescribeCertificateAuthorityCommand({ CertificateAuthorityArn: pcaArn })
  );

  const keyAlgorithm = response.CertificateAuthority?.CertificateAuthorityConfiguration?.KeyAlgorithm;
  console.log(`PCA key algorithm: ${keyAlgorithm}`);

  if (keyAlgorithm?.startsWith('RSA')) {
    return SigningAlgorithm.SHA256WITHRSA;
  } else if (keyAlgorithm?.startsWith('EC')) {
    return SigningAlgorithm.SHA256WITHECDSA;
  }

  console.warn(`Unknown key algorithm ${keyAlgorithm}, defaulting to SHA256WITHRSA`);
  return SigningAlgorithm.SHA256WITHRSA;
}

/**
 * Issue a certificate via ACM Private CA
 */
async function issueCertificatePca(
  hostname: string,
  csrPem: string,
  pcaArn: string,
  validityDays: number
): Promise<string> {
  console.log(`Issuing certificate for ${hostname} via ACM PCA: ${pcaArn}`);

  // Get signing algorithm based on PCA key type
  const signingAlgorithm = await getPcaSigningAlgorithm(pcaArn);
  console.log(`Using signing algorithm: ${signingAlgorithm}`);

  // Issue certificate
  const issueResponse = await acmPcaClient.send(
    new IssueCertificateCommand({
      CertificateAuthorityArn: pcaArn,
      Csr: Buffer.from(csrPem),
      SigningAlgorithm: signingAlgorithm,
      Validity: { Type: 'DAYS', Value: validityDays },
      IdempotencyToken: hostname.substring(0, 36), // Max 36 chars
    })
  );

  const certArn = issueResponse.CertificateArn;
  if (!certArn) {
    throw new Error('Certificate ARN not returned from IssueCertificate');
  }
  console.log(`Certificate issuance requested: ${certArn}`);

  // Wait for certificate to be issued (SDK waiter handles polling)
  console.log('Waiting for certificate issuance...');
  await waitUntilCertificateIssued(
    {
      client: acmPcaClient,
      maxWaitTime: 900, // 15 minutes (Lambda max timeout)
      minDelay: 1,
      maxDelay: 10,
    },
    {
      CertificateAuthorityArn: pcaArn,
      CertificateArn: certArn,
    }
  );

  // Get the certificate
  const getCertResponse = await acmPcaClient.send(
    new GetCertificateCommand({
      CertificateAuthorityArn: pcaArn,
      CertificateArn: certArn,
    })
  );

  let certPem = getCertResponse.Certificate;
  if (!certPem) {
    throw new Error('Certificate not returned from GetCertificate');
  }

  // Append certificate chain if present
  if (getCertResponse.CertificateChain) {
    certPem += '\n' + getCertResponse.CertificateChain;
  }

  console.log(`Certificate issued for ${hostname} (PCA mode)`);
  return certPem;
}

/**
 * Lambda handler for certificate issuance
 */
export async function handler(
  event: CloudFormationCustomResourceEvent
): Promise<CloudFormationCustomResourceResponse> {
  console.log('Received event:', JSON.stringify(event, null, 2));

  const requestType = event.RequestType;
  const properties = event.ResourceProperties as unknown as CertIssuerProperties;

  // Get physical resource ID (only available for Update/Delete)
  const getPhysicalResourceId = (): string => {
    if (requestType === 'Create') {
      return `cert-${properties.Hostname ?? 'unknown'}`;
    }
    return (event as CloudFormationCustomResourceUpdateEvent).PhysicalResourceId;
  };

  try {
    switch (requestType) {
      case 'Create':
      case 'Update': {
        const hostname = properties.Hostname;
        const caMode = properties.CAMode;
        const validityDays = Number(properties.ValidityDays ?? 365);

        if (!hostname) {
          throw new Error('Hostname is required');
        }

        console.log(`Processing host: ${hostname}, CA mode: ${caMode}`);

        // Generate key pair and CSR
        const { privateKeyPem, csrPem, publicKey } = await generateHostKeyAndCsr(hostname);

        let certPem: string;

        if (caMode === 'self-managed') {
          // Sign certificate using self-managed CA
          certPem = await signCertificateSelfManaged(
            hostname,
            publicKey,
            properties.CAPrivateKeySecretArn ?? '',
            properties.CACertificatePem ?? '',
            validityDays
          );
        } else if (caMode === 'pca-existing' || caMode === 'pca-managed') {
          // Issue certificate via ACM PCA
          const pcaArn = properties.PCAArn;
          if (!pcaArn) {
            throw new Error(`PCAArn is required for ${caMode} mode`);
          }
          certPem = await issueCertificatePca(hostname, csrPem, pcaArn, validityDays);
        } else {
          throw new Error(`Invalid CAMode: ${caMode}`);
        }

        const response: CertIssuerResponse = {
          Certificate: certPem,
          PrivateKey: privateKeyPem,
          Hostname: hostname,
        };

        return {
          Status: 'SUCCESS',
          PhysicalResourceId: `cert-${hostname}`,
          StackId: event.StackId,
          RequestId: event.RequestId,
          LogicalResourceId: event.LogicalResourceId,
          Data: response,
        };
      }

      case 'Delete': {
        // Nothing to delete - CloudFormation manages the secrets
        const physicalResourceId = getPhysicalResourceId();
        const hostname = physicalResourceId.replace('cert-', '');
        console.log(`DELETE event for host: ${hostname}`);
        console.log('CloudFormation will manage resource deletion');

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
      PhysicalResourceId: getPhysicalResourceId(),
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
    };
  }
}
