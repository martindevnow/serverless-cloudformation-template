import type { AWS } from "@serverless/typescript"

import ServerlessConstants from "./cloud/serverless-constants"
import * as resources from "./cloud/resources"

const serverlessConfiguration: AWS = {
  service: `${ServerlessConstants.client}-serverless`,
  frameworkVersion: "2",
  custom: {
    output: {
      handler: "scripts/serverless-output.handler",
      file: ".build/serverless-output.json",
    },
    assets: {
      // auto: true,
      // verbose: true,
      targets: [
        {
          bucket: { Ref: ServerlessConstants.ResourceNames.S3Bucket },
          files: [{ source: "public/", globs: ["**/*"] }],
        },
      ],
    },
  },
  plugins: ["serverless-stack-output", "serverless-s3-deploy"],
  provider: {
    name: "aws",
    runtime: "nodejs14.x",
    region: ServerlessConstants.region,
    // iam: {},
    environment: {
      AWS_NODEJS_CONNECTION_REUSE_ENABLED: "1",
    },
    lambdaHashingVersion: "20201221",
  },
  resources: {
    Resources: {
      [ServerlessConstants.ResourceNames.CloudFrontDistribution]:
        resources.CloudFront,
      [ServerlessConstants.ResourceNames.S3Bucket]: resources.S3Bucket,
      [ServerlessConstants.ResourceNames.S3BucketPolicy]:
        resources.S3BucketPolicy,
      [ServerlessConstants.ResourceNames.S3OriginAccessIdentity]:
        resources.S3OriginAccessIdentity,
      [ServerlessConstants.ResourceNames.CertificateManagerCertificate]:
        resources.CertificateManagerCertificate,
    },
    Outputs: resources.Outputs,
  },
}

module.exports = serverlessConfiguration
