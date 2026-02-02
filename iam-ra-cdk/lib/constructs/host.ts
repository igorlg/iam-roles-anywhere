/**
 * IAM Roles Anywhere Host Construct
 *
 * Creates all resources needed for a single host to authenticate via IAM Roles Anywhere:
 * - IAM Role with Roles Anywhere trust policy
 * - IAM Roles Anywhere Profile
 * - Host certificate (via custom resource)
 * - Secrets Manager secrets for certificate and private key
 * - SSM Parameters for discovery
 */

import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as rolesanywhere from 'aws-cdk-lib/aws-rolesanywhere';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';

import { CertificateIssuer } from './certificate-issuer';

export interface IamRaHostProps {
  /**
   * Hostname (becomes CN in certificate)
   * Must match: ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$
   */
  readonly hostname: string;

  /**
   * The certificate issuer construct
   */
  readonly certificateIssuer: CertificateIssuer;

  /**
   * Trust Anchor ARN
   */
  readonly trustAnchorArn: string;

  /**
   * SSM parameter prefix
   * @default '/iam-ra'
   */
  readonly ssmPrefix?: string;

  /**
   * IAM session duration in seconds
   * @default 3600 (1 hour)
   */
  readonly sessionDuration?: number;

  /**
   * Certificate validity in days
   * @default 365
   */
  readonly certificateValidityDays?: number;

  /**
   * Managed policy ARNs to attach to the role
   */
  readonly managedPolicyArns?: string[];

  /**
   * Additional inline policies for the role
   */
  readonly inlinePolicies?: Record<string, iam.PolicyDocument>;
}

/**
 * IAM Roles Anywhere Host construct
 *
 * Creates IAM Role, Profile, Certificate, and Secrets for a host.
 */
export class IamRaHost extends Construct {
  /**
   * The IAM Role for this host
   */
  public readonly role: iam.IRole;

  /**
   * The IAM Roles Anywhere Profile
   */
  public readonly profile: rolesanywhere.CfnProfile;

  /**
   * Secret containing the host certificate
   */
  public readonly certificateSecret: secretsmanager.ISecret;

  /**
   * Secret containing the host private key
   */
  public readonly privateKeySecret: secretsmanager.ISecret;

  /**
   * The hostname
   */
  public readonly hostname: string;

  private readonly ssmPrefix: string;

  constructor(scope: Construct, id: string, props: IamRaHostProps) {
    super(scope, id);

    this.hostname = props.hostname;
    this.ssmPrefix = props.ssmPrefix ?? '/iam-ra';
    const sessionDuration = props.sessionDuration ?? 3600;
    const certificateValidityDays = props.certificateValidityDays ?? 365;

    // Validate hostname
    if (!/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(this.hostname) && this.hostname.length < 2) {
      throw new Error(
        `Invalid hostname: ${this.hostname}. Must match pattern ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$ and be at least 2 characters.`
      );
    }

    // Create IAM Role with Roles Anywhere trust policy
    const role = new iam.Role(this, 'Role', {
      assumedBy: new iam.ServicePrincipal('rolesanywhere.amazonaws.com'),
      maxSessionDuration: cdk.Duration.seconds(sessionDuration),
      description: `IAM Roles Anywhere role for ${this.hostname}`,
    });

    // Add trust policy conditions
    role.assumeRolePolicy?.addStatements(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('rolesanywhere.amazonaws.com')],
        actions: ['sts:AssumeRole', 'sts:TagSession', 'sts:SetSourceIdentity'],
        conditions: {
          StringEquals: {
            'aws:PrincipalTag/x509Subject/CN': this.hostname,
          },
          ArnEquals: {
            'aws:SourceArn': props.trustAnchorArn,
          },
        },
      })
    );

    // Base policy - every host gets these permissions
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AllowGetCallerIdentity',
        effect: iam.Effect.ALLOW,
        actions: ['sts:GetCallerIdentity'],
        resources: ['*'],
      })
    );

    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AllowECRAuth',
        effect: iam.Effect.ALLOW,
        actions: ['ecr:GetAuthorizationToken'],
        resources: ['*'],
      })
    );

    role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AllowECRPull',
        effect: iam.Effect.ALLOW,
        actions: [
          'ecr:BatchCheckLayerAvailability',
          'ecr:GetDownloadUrlForLayer',
          'ecr:BatchGetImage',
        ],
        resources: [`arn:aws:ecr:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:repository/*`],
      })
    );

    // Attach managed policies if specified
    if (props.managedPolicyArns) {
      for (const arn of props.managedPolicyArns) {
        role.addManagedPolicy(iam.ManagedPolicy.fromManagedPolicyArn(this, `Policy-${arn.split('/').pop()}`, arn));
      }
    }

    // Add inline policies if specified
    if (props.inlinePolicies) {
      for (const [name, document] of Object.entries(props.inlinePolicies)) {
        role.attachInlinePolicy(
          new iam.Policy(this, `InlinePolicy-${name}`, {
            policyName: name,
            document,
          })
        );
      }
    }

    this.role = role;

    // Create IAM Roles Anywhere Profile
    this.profile = new rolesanywhere.CfnProfile(this, 'Profile', {
      name: `${this.hostname}-profile`,
      enabled: true,
      durationSeconds: sessionDuration,
      roleArns: [role.roleArn],
    });

    // Issue certificate via custom resource
    const certResource = new cdk.CustomResource(this, 'Certificate', {
      serviceToken: props.certificateIssuer.serviceToken,
      properties: {
        Hostname: this.hostname,
        ValidityDays: certificateValidityDays,
        ...props.certificateIssuer.getSigningCredentialsProperties(),
      },
    });

    // Get certificate and private key from custom resource
    const certificatePem = certResource.getAttString('Certificate');
    const privateKeyPem = certResource.getAttString('PrivateKey');

    // Store certificate in Secrets Manager
    this.certificateSecret = new secretsmanager.Secret(this, 'CertificateSecret', {
      secretName: `${this.ssmPrefix}-hosts/${this.hostname}/certificate`,
      description: `IAM Roles Anywhere certificate for ${this.hostname}`,
      secretStringValue: cdk.SecretValue.unsafePlainText(certificatePem),
    });

    // Store private key in Secrets Manager
    this.privateKeySecret = new secretsmanager.Secret(this, 'PrivateKeySecret', {
      secretName: `${this.ssmPrefix}-hosts/${this.hostname}/private-key`,
      description: `IAM Roles Anywhere private key for ${this.hostname}`,
      secretStringValue: cdk.SecretValue.unsafePlainText(privateKeyPem),
    });

    // SSM Parameters for host discovery
    new ssm.StringParameter(this, 'RoleArnParam', {
      parameterName: `${this.ssmPrefix}/hosts/${this.hostname}/role-arn`,
      description: `IAM Role ARN for ${this.hostname}`,
      stringValue: role.roleArn,
    });

    new ssm.StringParameter(this, 'ProfileArnParam', {
      parameterName: `${this.ssmPrefix}/hosts/${this.hostname}/profile-arn`,
      description: `IAM Roles Anywhere Profile ARN for ${this.hostname}`,
      stringValue: this.profile.attrProfileArn,
    });

    new ssm.StringParameter(this, 'TrustAnchorArnParam', {
      parameterName: `${this.ssmPrefix}/hosts/${this.hostname}/trust-anchor-arn`,
      description: `Trust Anchor ARN for ${this.hostname}`,
      stringValue: props.trustAnchorArn,
    });

    new ssm.StringParameter(this, 'RegionParam', {
      parameterName: `${this.ssmPrefix}/hosts/${this.hostname}/region`,
      description: `AWS Region for ${this.hostname}`,
      stringValue: cdk.Stack.of(this).region,
    });

    new ssm.StringParameter(this, 'CertSecretArnParam', {
      parameterName: `${this.ssmPrefix}/hosts/${this.hostname}/certificate-secret-arn`,
      description: `Certificate secret ARN for ${this.hostname}`,
      stringValue: this.certificateSecret.secretArn,
    });

    new ssm.StringParameter(this, 'KeySecretArnParam', {
      parameterName: `${this.ssmPrefix}/hosts/${this.hostname}/private-key-secret-arn`,
      description: `Private key secret ARN for ${this.hostname}`,
      stringValue: this.privateKeySecret.secretArn,
    });

    // Outputs
    new cdk.CfnOutput(this, 'RoleArn', {
      description: `IAM Role ARN for ${this.hostname}`,
      value: role.roleArn,
    });

    new cdk.CfnOutput(this, 'ProfileArn', {
      description: `IAM Roles Anywhere Profile ARN for ${this.hostname}`,
      value: this.profile.attrProfileArn,
    });

    new cdk.CfnOutput(this, 'CertificateSecretArn', {
      description: `Certificate secret ARN for ${this.hostname}`,
      value: this.certificateSecret.secretArn,
    });

    new cdk.CfnOutput(this, 'PrivateKeySecretArn', {
      description: `Private key secret ARN for ${this.hostname}`,
      value: this.privateKeySecret.secretArn,
    });
  }
}
