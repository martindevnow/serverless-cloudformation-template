import type { AWS } from "@serverless/typescript";

import ServerlessConstants from "./cloud/serverless-constants";
import AwsResources from "./cloud/resources/aws";

const serverlessConfiguration: AWS = {
  service: `${ServerlessConstants.client}-serverless`,
  frameworkVersion: "2",
  custom: {
    output: {
      handler: "cloud/scripts/serverless-output.handler",
      file: ".build/serverless-output.json",
    },
    assets: {
      // auto: true,
      // verbose: true,
      targets: [
        {
          bucket: { Ref: ServerlessConstants.StaticHosting.Logical.S3Bucket },
          files: [{ source: "public/", globs: ["**/*"] }],
        },
      ],
    },
  },
  plugins: ["serverless-stack-output", "serverless-s3-deploy"],
  provider: {
    name: "aws",
    profile: "yamenai",
    runtime: "nodejs14.x",
    region: ServerlessConstants.region,
    // iam: {},
    environment: {
      AWS_NODEJS_CONNECTION_REUSE_ENABLED: "1",
    },
    lambdaHashingVersion: "20201221",
  },
  resources: {
    Resources: AwsResources.Resources,
    Outputs: AwsResources.Outputs,
  },
};

module.exports = serverlessConfiguration;
