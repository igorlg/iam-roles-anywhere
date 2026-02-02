/**
 * Lambda Bundling Utilities
 *
 * Provides Lambda code loading that works in both:
 * - Development mode: Uses NodejsFunction with esbuild bundling at synth time
 * - Packaged mode: Uses pre-bundled code from LAMBDA_BUNDLE_PATH
 *
 * The LAMBDA_BUNDLE_PATH environment variable is set by the Nix wrapper
 * to point to pre-bundled Lambda handlers.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNodejs from 'aws-cdk-lib/aws-lambda-nodejs';

/**
 * Check if we're running in packaged mode (pre-bundled lambdas available)
 */
export function isPackagedMode(): boolean {
  const bundlePath = process.env.LAMBDA_BUNDLE_PATH;
  return bundlePath !== undefined && fs.existsSync(bundlePath);
}

/**
 * Get the path to a pre-bundled lambda
 */
function getBundledLambdaPath(lambdaName: string): string {
  const bundlePath = process.env.LAMBDA_BUNDLE_PATH;
  if (!bundlePath) {
    throw new Error('LAMBDA_BUNDLE_PATH not set');
  }
  return path.join(bundlePath, lambdaName);
}

export interface LambdaFunctionProps {
  /**
   * Lambda name (matches directory in bundled-lambdas/)
   */
  readonly lambdaName: string;

  /**
   * Path to TypeScript source file (for development mode)
   */
  readonly entry: string;

  /**
   * Lambda description
   */
  readonly description?: string;

  /**
   * Lambda timeout
   * @default Duration.minutes(1)
   */
  readonly timeout?: cdk.Duration;

  /**
   * Lambda memory size
   * @default 256
   */
  readonly memorySize?: number;

  /**
   * Environment variables
   */
  readonly environment?: Record<string, string>;
}

/**
 * Create a Lambda function that works in both dev and packaged modes
 *
 * In development mode: Uses NodejsFunction to bundle at synth time
 * In packaged mode: Uses pre-bundled code from LAMBDA_BUNDLE_PATH
 */
export function createLambdaFunction(
  scope: Construct,
  id: string,
  props: LambdaFunctionProps
): lambda.Function {
  const runtime = lambda.Runtime.NODEJS_20_X;
  const architecture = lambda.Architecture.ARM_64;
  const timeout = props.timeout ?? cdk.Duration.minutes(1);
  const memorySize = props.memorySize ?? 256;

  if (isPackagedMode()) {
    // Packaged mode: use pre-bundled code
    const codePath = getBundledLambdaPath(props.lambdaName);

    return new lambda.Function(scope, id, {
      description: props.description,
      runtime,
      architecture,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(codePath),
      timeout,
      memorySize,
      environment: props.environment,
    });
  } else {
    // Development mode: bundle at synth time with NodejsFunction
    return new lambdaNodejs.NodejsFunction(scope, id, {
      description: props.description,
      entry: props.entry,
      handler: 'handler',
      runtime,
      architecture,
      timeout,
      memorySize,
      environment: props.environment,
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'node20',
        externalModules: [],
      },
    });
  }
}
