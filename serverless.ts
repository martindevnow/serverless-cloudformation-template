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
  },
  plugins: ["serverless-stack-output"],
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
    // Resources: {
    //   [ServerlessConstants.Resources.BucketName]: resources.S3BucketResource,
    //   [ServerlessConstants.Resources.PolicyName]:
    //     resources.StaticSiteS3BucketPolicy,
    //   [ServerlessConstants.Resources.CertName]: resources.StaticSiteCert,
    //   [ServerlessConstants.Resources.CloudFrontName]:
    //     resources.CloudFrontDistribution,
    //   [ServerlessConstants.Resources.DnsResourceName]:
    //     resources.DnsRecordResource,
    // },
    // Outputs: resources.Outputs,
    Resources: {
      [ServerlessConstants.ResourceNames.CloudFrontDistribution]:
        resources.CloudFront,
      [ServerlessConstants.ResourceNames.S3Bucket]: resources.S3Bucket,
      [ServerlessConstants.ResourceNames.CertificateManagerCertificate]:
        resources.CertificateManagerCertificate,
    },
    Outputs: resources.Outputs,
  },
}

module.exports = serverlessConfiguration
