/**
 * CDK-Managed ACM Private CA Construct
 *
 * Creates a new ACM Private CA via CDK:
 * - Creates ROOT type Certificate Authority
 * - Self-signs the CA certificate
 * - Activates the CA
 *
 * Cost: $400/month
 * Recommended for: New deployments that need PCA features (CRL, audit logging, etc.)
 */

import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as acmpca from 'aws-cdk-lib/aws-acmpca';
import * as rolesanywhere from 'aws-cdk-lib/aws-rolesanywhere';
import * as ssm from 'aws-cdk-lib/aws-ssm';

import {
  ICertificateAuthority,
  SigningCredentials,
  ManagedPcaCAProps,
} from './types';

/**
 * CDK-managed ACM Private CA implementation
 *
 * Creates and activates a new ROOT Certificate Authority.
 */
export class ManagedPcaCA extends Construct implements ICertificateAuthority {
  public readonly mode = 'pca-managed' as const;

  /**
   * The ACM Private CA
   */
  public readonly certificateAuthority: acmpca.CfnCertificateAuthority;

  /**
   * The CA certificate resource
   */
  public readonly caCertificate: acmpca.CfnCertificate;

  /**
   * ARN of the ACM Private CA
   */
  public readonly pcaArn: string;

  /**
   * Trust anchor source for IAM Roles Anywhere
   */
  public readonly trustAnchorSource: rolesanywhere.CfnTrustAnchor.SourceProperty;

  /**
   * SSM Parameter storing the PCA ARN
   */
  public readonly pcaArnParameter: ssm.StringParameter;

  private readonly ssmPrefix: string;

  constructor(scope: Construct, id: string, props: ManagedPcaCAProps = {}) {
    super(scope, id);

    this.ssmPrefix = props.ssmPrefix ?? '/iam-ra';
    const keyAlgorithm = props.keyAlgorithm ?? 'EC_prime256v1';
    const validityYears = props.validityYears ?? 10;
    const subjectCountry = props.subjectCountry ?? 'US';
    const subjectOrganization = props.subjectOrganization ?? 'IAM Roles Anywhere';
    const subjectCommonName = props.subjectCommonName ?? 'Managed CA';

    // Determine signing algorithm based on key type
    const isEcKey = keyAlgorithm.startsWith('EC_');
    const signingAlgorithm = isEcKey ? 'SHA256WITHECDSA' : 'SHA256WITHRSA';

    // Create the Certificate Authority
    this.certificateAuthority = new acmpca.CfnCertificateAuthority(this, 'CA', {
      type: 'ROOT',
      keyAlgorithm: keyAlgorithm,
      signingAlgorithm: signingAlgorithm,
      subject: {
        country: subjectCountry,
        organization: subjectOrganization,
        commonName: subjectCommonName,
      },
      revocationConfiguration: {
        crlConfiguration: {
          enabled: false,
        },
      },
    });

    this.pcaArn = this.certificateAuthority.attrArn;

    // Create and sign the CA certificate (self-signed for ROOT)
    this.caCertificate = new acmpca.CfnCertificate(this, 'CACert', {
      certificateAuthorityArn: this.pcaArn,
      certificateSigningRequest: this.certificateAuthority.attrCertificateSigningRequest,
      signingAlgorithm: signingAlgorithm,
      templateArn: 'arn:aws:acm-pca:::template/RootCACertificate/V1',
      validity: {
        type: 'YEARS',
        value: validityYears,
      },
    });

    // Activate the CA
    const activation = new acmpca.CfnCertificateAuthorityActivation(this, 'Activation', {
      certificateAuthorityArn: this.pcaArn,
      certificate: this.caCertificate.attrCertificate,
      status: 'ACTIVE',
    });

    // Ensure proper dependency ordering
    activation.addDependency(this.caCertificate);

    // Store PCA ARN in SSM for cross-stack reference
    this.pcaArnParameter = new ssm.StringParameter(this, 'PcaArn', {
      parameterName: `${this.ssmPrefix}/pca-arn`,
      description: 'ACM Private CA ARN for IAM Roles Anywhere (CDK-managed)',
      stringValue: this.pcaArn,
    });

    // Trust anchor references the PCA directly
    this.trustAnchorSource = {
      sourceType: 'AWS_ACM_PCA',
      sourceData: {
        acmPcaArn: this.pcaArn,
      },
    };

    // Output the CA ARN
    new cdk.CfnOutput(this, 'CaArn', {
      description: 'ACM Private CA ARN',
      value: this.pcaArn,
    });
  }

  /**
   * Get signing credentials for certificate issuance
   */
  getSigningCredentials(): SigningCredentials {
    return {
      mode: this.mode,
      pcaArn: this.pcaArn,
    };
  }

  /**
   * Grant certificate issuance permissions
   * For PCA mode, grants acm-pca:IssueCertificate, GetCertificate, DescribeCertificateAuthority
   */
  grantCertificateIssuance(grantee: lambda.IFunction): void {
    grantee.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'acm-pca:DescribeCertificateAuthority',
          'acm-pca:IssueCertificate',
          'acm-pca:GetCertificate',
        ],
        resources: [this.pcaArn],
      })
    );
  }
}
