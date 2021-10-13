import { AWS_IAM_Policy, AWS_IAM_User } from "../aws.types";
import ServerlessConstants from "../serverless-constants";

const DeployPolicy: AWS_IAM_Policy = {
  Type: "AWS::IAM::Policy",
  Properties: {
    PolicyName: ServerlessConstants.GatsbyCloud.Name.Policy,
    PolicyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: ["s3:GetBucketLocation"],
          Resource: ["arn:aws:s3:::*"],
        },
        {
          Effect: "Allow",
          Action: ["s3:ListBucket"],
          Resource: `arn:aws:s3:::${ServerlessConstants.StaticHosting.Names.S3Bucket}`,
        },
        {
          Effect: "Allow",
          Action: ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
          Resource: `arn:aws:s3:::${ServerlessConstants.StaticHosting.Names.S3Bucket}/*`,
        },
        {
          Effect: "Allow",
          Action: ["cloudfront:CreateInvalidation"],
          Resource: "*",
        },
      ],
    },
  },
};

export const User: AWS_IAM_User = {
  Type: "AWS::IAM::User",
  Properties: {
    Policies: [
      {
        PolicyName: DeployPolicy.Properties.PolicyName,
        PolicyDocument: DeployPolicy.Properties.PolicyDocument,
      },
    ],
  },
};

export const AccessKey /*: AWS_IAM_AccessKey */ = {
  Type: "AWS::IAM::AccessKey",
  Properties: {
    UserName: {
      Ref: ServerlessConstants.GatsbyCloud.Logical.User,
    },
  },
};

export const Resources = {
  [ServerlessConstants.GatsbyCloud.Logical.User]: User,
  [ServerlessConstants.GatsbyCloud.Logical.AccessKey]: AccessKey,
};

export const Outputs = {
  [ServerlessConstants.GatsbyCloud.Outputs.AccessKey]: {
    Value: { Ref: ServerlessConstants.GatsbyCloud.Logical.AccessKey },
  },
  [ServerlessConstants.GatsbyCloud.Outputs.SecretAccessKey]: {
    Value: {
      "Fn::GetAtt": [
        ServerlessConstants.GatsbyCloud.Logical.AccessKey,
        "SecretAccessKey",
      ],
    },
  },
};
