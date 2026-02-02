/**
 * Certificate Authority Types and Interfaces
 *
 * Defines the polymorphic abstraction for different CA modes:
 * - self-managed: Lambda-generated CA (recommended for <40 hosts)
 * - pca-existing: Use existing ACM Private CA
 * - pca-managed: Create new ACM Private CA via CDK
 */

import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as rolesanywhere from 'aws-cdk-lib/aws-rolesanywhere';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

/**
 * CA operation modes
 */
export type CAMode = 'self-managed' | 'pca-existing' | 'pca-managed';

/**
 * Signing credentials needed by the certificate issuer
 */
export interface SigningCredentials {
  /**
   * CA mode determines how certificates are signed
   */
  readonly mode: CAMode;

  /**
   * CA Certificate PEM (self-managed mode)
   * For PCA modes, this is undefined - certs are issued via PCA API
   */
  readonly caCertificatePem?: string;

  /**
   * CA Private Key secret (self-managed mode)
   * The secret containing the CA private key PEM
   */
  readonly caPrivateKeySecret?: secretsmanager.ISecret;

  /**
   * ACM Private CA ARN (PCA modes)
   */
  readonly pcaArn?: string;
}

/**
 * Interface for Certificate Authority implementations
 *
 * Each implementation provides:
 * 1. Trust anchor source configuration
 * 2. Signing credentials for certificate issuance
 * 3. IAM permissions granting for Lambda functions
 */
export interface ICertificateAuthority {
  /**
   * The CA mode
   */
  readonly mode: CAMode;

  /**
   * Trust anchor source configuration for IAM Roles Anywhere
   * This is passed directly to CfnTrustAnchor.SourceProperty
   */
  readonly trustAnchorSource: rolesanywhere.CfnTrustAnchor.SourceProperty;

  /**
   * Get signing credentials for certificate issuance
   * The certificate issuer Lambda uses these to sign host certificates
   */
  getSigningCredentials(): SigningCredentials;

  /**
   * Grant the necessary permissions to issue certificates
   * - Self-managed: Grant secret read access for CA private key
   * - PCA modes: Grant ACM PCA IssueCertificate, GetCertificate permissions
   */
  grantCertificateIssuance(grantee: lambda.IFunction): void;
}

/**
 * Common properties for all CA construct types
 */
export interface CertificateAuthorityBaseProps {
  /**
   * SSM parameter prefix for storing CA configuration
   * @default '/iam-ra'
   */
  readonly ssmPrefix?: string;
}

/**
 * Properties for self-managed CA
 */
export interface SelfManagedCAProps extends CertificateAuthorityBaseProps {
  /**
   * CA certificate validity in years
   * @default 10
   */
  readonly validityYears?: number;
}

/**
 * Properties for existing ACM Private CA
 */
export interface ExistingPcaCAProps extends CertificateAuthorityBaseProps {
  /**
   * ARN of the existing ACM Private CA
   */
  readonly pcaArn: string;
}

/**
 * Properties for CDK-managed ACM Private CA
 */
export interface ManagedPcaCAProps extends CertificateAuthorityBaseProps {
  /**
   * Key algorithm for the PCA
   * @default 'EC_prime256v1'
   */
  readonly keyAlgorithm?: 'EC_prime256v1' | 'EC_secp384r1' | 'RSA_2048' | 'RSA_4096';

  /**
   * CA certificate validity in years
   * @default 10
   */
  readonly validityYears?: number;

  /**
   * Subject country code (2 letters)
   * @default 'US'
   */
  readonly subjectCountry?: string;

  /**
   * Subject organization
   * @default 'IAM Roles Anywhere'
   */
  readonly subjectOrganization?: string;

  /**
   * Subject common name
   * @default 'Managed CA'
   */
  readonly subjectCommonName?: string;
}
