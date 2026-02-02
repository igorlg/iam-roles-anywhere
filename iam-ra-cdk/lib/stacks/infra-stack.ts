/**
 * IAM Roles Anywhere Infrastructure Stack
 *
 * Creates shared infrastructure for IAM Roles Anywhere:
 * - Certificate Authority (self-managed, existing PCA, or managed PCA)
 * - Trust Anchor
 * - Certificate Issuer (Lambda + Provider)
 *
 * This stack is deployed once per AWS account/region.
 * Host stacks depend on resources created by this stack.
 */

import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as rolesanywhere from 'aws-cdk-lib/aws-rolesanywhere';
import * as ssm from 'aws-cdk-lib/aws-ssm';

import {
  ICertificateAuthority,
  SelfManagedCA,
  ExistingPcaCA,
  ManagedPcaCA,
  SelfManagedCAProps,
  ExistingPcaCAProps,
  ManagedPcaCAProps,
} from '../constructs/certificate-authority/index';
import { CertificateIssuer } from '../constructs/certificate-issuer';

/**
 * CA configuration - exactly one mode should be specified
 */
export type CAConfig =
  | { mode: 'self-managed'; props?: SelfManagedCAProps }
  | { mode: 'pca-existing'; props: ExistingPcaCAProps }
  | { mode: 'pca-managed'; props?: ManagedPcaCAProps };

export interface IamRaInfraStackProps extends cdk.StackProps {
  /**
   * CA configuration
   * @default { mode: 'self-managed' }
   */
  readonly caConfig?: CAConfig;

  /**
   * SSM parameter prefix
   * @default '/iam-ra'
   */
  readonly ssmPrefix?: string;
}

/**
 * IAM Roles Anywhere Infrastructure Stack
 */
export class IamRaInfraStack extends cdk.Stack {
  /**
   * The Certificate Authority construct
   */
  public readonly certificateAuthority: ICertificateAuthority;

  /**
   * The Trust Anchor
   */
  public readonly trustAnchor: rolesanywhere.CfnTrustAnchor;

  /**
   * The Certificate Issuer
   */
  public readonly certificateIssuer: CertificateIssuer;

  /**
   * SSM parameter prefix
   */
  public readonly ssmPrefix: string;

  constructor(scope: Construct, id: string, props: IamRaInfraStackProps = {}) {
    super(scope, id, props);

    this.ssmPrefix = props.ssmPrefix ?? '/iam-ra';
    const caConfig = props.caConfig ?? { mode: 'self-managed' };

    // Create Certificate Authority based on mode
    this.certificateAuthority = this.createCertificateAuthority(caConfig);

    // Create Trust Anchor
    this.trustAnchor = new rolesanywhere.CfnTrustAnchor(this, 'TrustAnchor', {
      name: `${this.stackName}-trust-anchor`,
      enabled: true,
      source: this.certificateAuthority.trustAnchorSource,
    });

    // Store Trust Anchor ARN in SSM
    new ssm.StringParameter(this, 'TrustAnchorArn', {
      parameterName: `${this.ssmPrefix}/trust-anchor-arn`,
      description: 'IAM Roles Anywhere Trust Anchor ARN',
      stringValue: this.trustAnchor.attrTrustAnchorArn,
    });

    // Store CA Mode in SSM
    new ssm.StringParameter(this, 'CAMode', {
      parameterName: `${this.ssmPrefix}/ca-mode`,
      description: 'IAM Roles Anywhere CA Mode',
      stringValue: this.certificateAuthority.mode,
    });

    // Store Region in SSM
    new ssm.StringParameter(this, 'Region', {
      parameterName: `${this.ssmPrefix}/region`,
      description: 'AWS Region for IAM Roles Anywhere',
      stringValue: this.region,
    });

    // Create Certificate Issuer
    this.certificateIssuer = new CertificateIssuer(this, 'CertIssuer', {
      certificateAuthority: this.certificateAuthority,
      ssmPrefix: this.ssmPrefix,
    });

    // Outputs
    new cdk.CfnOutput(this, 'TrustAnchorArnOutput', {
      description: 'IAM Roles Anywhere Trust Anchor ARN',
      value: this.trustAnchor.attrTrustAnchorArn,
      exportName: `${this.stackName}-TrustAnchorArn`,
    });

    new cdk.CfnOutput(this, 'CAModeOutput', {
      description: 'Certificate Authority mode',
      value: this.certificateAuthority.mode,
      exportName: `${this.stackName}-CAMode`,
    });

    new cdk.CfnOutput(this, 'CertIssuerArnOutput', {
      description: 'Certificate Issuer Lambda ARN',
      value: this.certificateIssuer.function.functionArn,
      exportName: `${this.stackName}-CertIssuerArn`,
    });

    new cdk.CfnOutput(this, 'SSMPrefixOutput', {
      description: 'SSM Parameter prefix for this deployment',
      value: this.ssmPrefix,
      exportName: `${this.stackName}-SSMPrefix`,
    });
  }

  /**
   * Create the appropriate CA construct based on configuration
   */
  private createCertificateAuthority(config: CAConfig): ICertificateAuthority {
    switch (config.mode) {
      case 'self-managed':
        return new SelfManagedCA(this, 'CA', {
          ssmPrefix: this.ssmPrefix,
          ...config.props,
        });

      case 'pca-existing':
        return new ExistingPcaCA(this, 'CA', {
          ssmPrefix: this.ssmPrefix,
          ...config.props,
        });

      case 'pca-managed':
        return new ManagedPcaCA(this, 'CA', {
          ssmPrefix: this.ssmPrefix,
          ...config.props,
        });

      default:
        throw new Error(`Unknown CA mode: ${(config as { mode: string }).mode}`);
    }
  }
}
