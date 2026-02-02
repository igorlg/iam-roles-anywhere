/**
 * Certificate Issuer Construct
 *
 * Provides the shared certificate issuer Lambda and Provider for host stacks.
 * This construct is created once in the infra stack and referenced by host stacks.
 */

import * as path from 'node:path';
import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as ssm from 'aws-cdk-lib/aws-ssm';

import { createLambdaFunction } from '../util/lambda-bundling';
import { ICertificateAuthority } from './certificate-authority/index';

export interface CertificateIssuerProps {
  /**
   * The Certificate Authority to use for signing
   */
  readonly certificateAuthority: ICertificateAuthority;

  /**
   * SSM parameter prefix
   * @default '/iam-ra'
   */
  readonly ssmPrefix?: string;
}

/**
 * Certificate Issuer construct
 *
 * Creates the Lambda function and Provider for issuing host certificates.
 */
export class CertificateIssuer extends Construct {
  /**
   * The certificate issuer Lambda function
   */
  public readonly function: lambda.IFunction;

  /**
   * The Provider for CloudFormation custom resources
   */
  public readonly provider: cr.Provider;

  /**
   * SSM Parameter containing the Lambda ARN
   */
  public readonly functionArnParameter: ssm.StringParameter;

  private readonly ssmPrefix: string;
  private readonly ca: ICertificateAuthority;

  constructor(scope: Construct, id: string, props: CertificateIssuerProps) {
    super(scope, id);

    this.ssmPrefix = props.ssmPrefix ?? '/iam-ra';
    this.ca = props.certificateAuthority;

    // Certificate Issuer Lambda (uses pre-bundled code in packaged mode)
    const certIssuerFn = createLambdaFunction(this, 'Function', {
      lambdaName: 'cert-issuer',
      entry: path.join(__dirname, '../lambdas/cert-issuer.ts'),
      description: 'Issues host certificates for IAM Roles Anywhere',
      timeout: cdk.Duration.minutes(15), // Maximum for SDK waiter
      memorySize: 256,
    });

    // Grant certificate issuance permissions based on CA mode
    this.ca.grantCertificateIssuance(certIssuerFn);

    this.function = certIssuerFn;

    // Create Provider for custom resources
    // Note: We don't use isCompleteHandler - the Lambda uses SDK waiters internally
    // for async PCA certificate issuance. The Lambda timeout of 15 minutes
    // is sufficient for this use case.
    this.provider = new cr.Provider(this, 'Provider', {
      onEventHandler: certIssuerFn,
    });

    // Store Lambda ARN in SSM for cross-stack reference
    this.functionArnParameter = new ssm.StringParameter(this, 'FunctionArn', {
      parameterName: `${this.ssmPrefix}/certificate-issuer-arn`,
      description: 'Certificate Issuer Lambda ARN (shared by host stacks)',
      stringValue: certIssuerFn.functionArn,
    });
  }

  /**
   * Get the service token for custom resources
   */
  get serviceToken(): string {
    return this.provider.serviceToken;
  }

  /**
   * Get signing credentials for custom resource properties
   */
  getSigningCredentialsProperties(): Record<string, string> {
    const creds = this.ca.getSigningCredentials();

    const props: Record<string, string> = {
      CAMode: creds.mode,
    };

    if (creds.mode === 'self-managed') {
      if (creds.caPrivateKeySecret) {
        props['CAPrivateKeySecretArn'] = creds.caPrivateKeySecret.secretArn;
      }
      if (creds.caCertificatePem) {
        props['CACertificatePem'] = creds.caCertificatePem;
      }
    } else {
      if (creds.pcaArn) {
        props['PCAArn'] = creds.pcaArn;
      }
    }

    return props;
  }
}
