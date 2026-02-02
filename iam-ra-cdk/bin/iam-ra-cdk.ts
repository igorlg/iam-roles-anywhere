#!/usr/bin/env node
/**
 * IAM Roles Anywhere CDK Application
 *
 * This app creates two types of stacks:
 * 1. IamRaInfraStack - Shared infrastructure (CA, Trust Anchor, Cert Issuer)
 * 2. IamRaHostStack - Per-host resources (Role, Profile, Certificate, Secrets)
 *
 * Usage via CDK CLI:
 *   # Deploy infrastructure (once per account/region)
 *   cdk deploy IamRaInfraStack
 *
 *   # Deploy a host
 *   cdk deploy IamRaHostStack-myhost -c hostname=myhost
 *
 * Usage via CLI (iam-ra-cli):
 *   iam-ra init       # Deploys IamRaInfraStack
 *   iam-ra onboard    # Deploys IamRaHostStack-<hostname>
 *
 * Context Parameters:
 *   -c caMode=self-managed|pca-existing|pca-managed  (default: self-managed)
 *   -c pcaArn=arn:aws:acm-pca:...                    (required for pca-existing)
 *   -c hostname=myhost                               (required for host stack)
 *   -c ssmPrefix=/iam-ra                             (default: /iam-ra)
 */

import * as cdk from 'aws-cdk-lib';
import { IamRaInfraStack, CAConfig } from '../lib/stacks/infra-stack';
import { IamRaHostStack } from '../lib/stacks/host-stack';

const app = new cdk.App();

// Get environment from CDK context or environment variables
const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// Get configuration from CDK context
const caMode = app.node.tryGetContext('caMode') ?? 'self-managed';
const pcaArn = app.node.tryGetContext('pcaArn');
const hostname = app.node.tryGetContext('hostname');
const ssmPrefix = app.node.tryGetContext('ssmPrefix') ?? '/iam-ra';

// Build CA configuration
function buildCaConfig(): CAConfig {
  switch (caMode) {
    case 'self-managed':
      return { mode: 'self-managed' };
    case 'pca-existing':
      if (!pcaArn) {
        throw new Error('pcaArn context is required for pca-existing mode');
      }
      return { mode: 'pca-existing', props: { pcaArn } };
    case 'pca-managed':
      return { mode: 'pca-managed' };
    default:
      throw new Error(`Unknown caMode: ${caMode}`);
  }
}

// Create Infrastructure Stack (always created for synthesis)
const infraStack = new IamRaInfraStack(app, 'IamRaInfraStack', {
  env,
  caConfig: buildCaConfig(),
  ssmPrefix,
  description: 'IAM Roles Anywhere infrastructure (CA, Trust Anchor, Certificate Issuer)',
});

// Create Host Stack if hostname is provided
if (hostname) {
  new IamRaHostStack(app, `IamRaHostStack-${hostname}`, {
    env,
    hostname,
    infraStack,
    description: `IAM Roles Anywhere host: ${hostname}`,
  });
}

app.synth();
