/**
 * Self-Managed Certificate Authority Construct
 *
 * Creates a self-managed CA using a Lambda custom resource:
 * - Generates EC P-256 CA key pair
 * - Creates self-signed CA certificate
 * - Stores CA private key in Secrets Manager
 * - Stores CA certificate in SSM Parameter
 *
 * Recommended for deployments with <40 hosts (lower cost than ACM PCA).
 */

import * as path from 'node:path';
import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as rolesanywhere from 'aws-cdk-lib/aws-rolesanywhere';

import { createLambdaFunction } from '../../util/lambda-bundling';
import {
  ICertificateAuthority,
  SigningCredentials,
  SelfManagedCAProps,
} from './types';

/**
 * Self-managed CA implementation
 *
 * Uses a Lambda function to generate the CA certificate and key pair.
 * The CA private key is stored in Secrets Manager (crown jewels).
 * The CA certificate (public) is stored in SSM Parameter Store.
 */
export class SelfManagedCA extends Construct implements ICertificateAuthority {
  public readonly mode = 'self-managed' as const;

  /**
   * The CA certificate in PEM format
   */
  public readonly caCertificatePem: string;

  /**
   * Secret containing the CA private key
   */
  public readonly caPrivateKeySecret: secretsmanager.ISecret;

  /**
   * SSM Parameter containing the CA certificate
   */
  public readonly caCertificateParameter: ssm.StringParameter;

  /**
   * Trust anchor source for IAM Roles Anywhere
   */
  public readonly trustAnchorSource: rolesanywhere.CfnTrustAnchor.SourceProperty;

  private readonly ssmPrefix: string;

  constructor(scope: Construct, id: string, props: SelfManagedCAProps = {}) {
    super(scope, id);

    this.ssmPrefix = props.ssmPrefix ?? '/iam-ra';
    const validityYears = props.validityYears ?? 10;

    // CA Generator Lambda (uses pre-bundled code in packaged mode)
    const caGeneratorFn = createLambdaFunction(this, 'CaGeneratorFn', {
      lambdaName: 'ca-generator',
      entry: path.join(__dirname, '../../lambdas/ca-generator.ts'),
      description: 'Generates self-managed CA for IAM Roles Anywhere',
      timeout: cdk.Duration.minutes(1),
      memorySize: 256,
    });

    // Custom Resource Provider
    const provider = new cr.Provider(this, 'CaGeneratorProvider', {
      onEventHandler: caGeneratorFn,
    });

    // Custom Resource to generate CA
    const caResource = new cdk.CustomResource(this, 'CaGenerator', {
      serviceToken: provider.serviceToken,
      properties: {
        ValidityYears: validityYears,
      },
    });

    // Get outputs from custom resource
    this.caCertificatePem = caResource.getAttString('CACertificate');
    const caPrivateKeyPem = caResource.getAttString('CAPrivateKey');

    // Store CA private key in Secrets Manager (crown jewels!)
    this.caPrivateKeySecret = new secretsmanager.Secret(this, 'CaPrivateKey', {
      secretName: `${this.ssmPrefix}/ca-private-key`,
      description: 'IAM Roles Anywhere self-managed CA private key (crown jewels)',
      secretStringValue: cdk.SecretValue.unsafePlainText(caPrivateKeyPem),
    });

    // Store CA certificate in SSM (public, can be shared)
    this.caCertificateParameter = new ssm.StringParameter(this, 'CaCertificate', {
      parameterName: `${this.ssmPrefix}/ca-certificate`,
      description: 'IAM Roles Anywhere self-managed CA certificate (public)',
      stringValue: this.caCertificatePem,
    });

    // Trust anchor uses certificate bundle with the CA cert
    this.trustAnchorSource = {
      sourceType: 'CERTIFICATE_BUNDLE',
      sourceData: {
        x509CertificateData: this.caCertificatePem,
      },
    };
  }

  /**
   * Get signing credentials for certificate issuance
   */
  getSigningCredentials(): SigningCredentials {
    return {
      mode: this.mode,
      caCertificatePem: this.caCertificatePem,
      caPrivateKeySecret: this.caPrivateKeySecret,
    };
  }

  /**
   * Grant certificate issuance permissions
   * For self-managed CA, this grants read access to the CA private key secret
   */
  grantCertificateIssuance(grantee: cdk.aws_lambda.IFunction): void {
    this.caPrivateKeySecret.grantRead(grantee);
  }
}
