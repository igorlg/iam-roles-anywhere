/**
 * IAM Roles Anywhere Host Stack
 *
 * Creates resources for a single host:
 * - IAM Role with Roles Anywhere trust policy
 * - IAM Roles Anywhere Profile
 * - Host certificate
 * - Secrets Manager secrets
 * - SSM Parameters
 *
 * This stack is deployed once per host.
 * Requires the infra stack to be deployed first.
 */

import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';

import { IamRaHost } from '../constructs/host';
import { IamRaInfraStack } from './infra-stack';

export interface IamRaHostStackProps extends cdk.StackProps {
  /**
   * Hostname (becomes CN in certificate)
   */
  readonly hostname: string;

  /**
   * Reference to the infra stack
   */
  readonly infraStack: IamRaInfraStack;

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
 * IAM Roles Anywhere Host Stack
 */
export class IamRaHostStack extends cdk.Stack {
  /**
   * The host construct
   */
  public readonly host: IamRaHost;

  constructor(scope: Construct, id: string, props: IamRaHostStackProps) {
    super(scope, id, props);

    // Create the host
    this.host = new IamRaHost(this, 'Host', {
      hostname: props.hostname,
      certificateIssuer: props.infraStack.certificateIssuer,
      trustAnchorArn: props.infraStack.trustAnchor.attrTrustAnchorArn,
      ssmPrefix: props.infraStack.ssmPrefix,
      sessionDuration: props.sessionDuration,
      certificateValidityDays: props.certificateValidityDays,
      managedPolicyArns: props.managedPolicyArns,
      inlinePolicies: props.inlinePolicies,
    });

    // Add dependency on infra stack
    this.addDependency(props.infraStack);
  }
}
