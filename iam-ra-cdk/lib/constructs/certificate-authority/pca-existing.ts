/**
 * Existing ACM Private CA Construct
 *
 * Uses an existing ACM Private CA for certificate issuance.
 * The CA must already be created and active.
 *
 * Cost: $400/month for the PCA (shared across all usage)
 * Recommended for: Enterprise deployments, existing PCA infrastructure
 */

import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as rolesanywhere from 'aws-cdk-lib/aws-rolesanywhere';
import * as ssm from 'aws-cdk-lib/aws-ssm';

import {
  ICertificateAuthority,
  SigningCredentials,
  ExistingPcaCAProps,
} from './types';

/**
 * Existing ACM Private CA implementation
 *
 * References an existing ACM Private CA by ARN.
 * The PCA must be in ACTIVE state.
 */
export class ExistingPcaCA extends Construct implements ICertificateAuthority {
  public readonly mode = 'pca-existing' as const;

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

  constructor(scope: Construct, id: string, props: ExistingPcaCAProps) {
    super(scope, id);

    this.ssmPrefix = props.ssmPrefix ?? '/iam-ra';
    this.pcaArn = props.pcaArn;

    // Store PCA ARN in SSM for cross-stack reference
    this.pcaArnParameter = new ssm.StringParameter(this, 'PcaArn', {
      parameterName: `${this.ssmPrefix}/pca-arn`,
      description: 'ACM Private CA ARN for IAM Roles Anywhere',
      stringValue: this.pcaArn,
    });

    // Trust anchor references the PCA directly
    this.trustAnchorSource = {
      sourceType: 'AWS_ACM_PCA',
      sourceData: {
        acmPcaArn: this.pcaArn,
      },
    };
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
