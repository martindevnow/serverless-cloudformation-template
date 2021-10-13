const globals = {
  client: "yamenai",
  stage: process.env.STAGE || "dev",
  project: "blogstarter",
  region: "us-east-1",
  domain: "yamenai.com",
} as const;

export const ServerlessConstants = {
  ...globals,
  GatsbyCloud: {
    Name: {
      Policy: "GatsbyCloudDeployPolicy",
    },
    Logical: {
      User: "GCUser",
      Policy: "GCPolicy",
      AccessKey: "GCAccessKey",
    },
    Outputs: {
      AccessKey: "GCAccessKey",
      SecretAccessKey: "GCSecretAccessKey",
    },
  },
  StaticHosting: {
    Names: {
      S3Bucket: `${globals.project}-${globals.stage}`,
    },
    Logical: {
      S3Bucket: "SHS3Bucket",
      S3OriginAccessIdentity: "SHS3OriginAccessIdentity",
      S3CloudFrontBucketPolicy: "SHS3CloudFrontBucketPolicy",
      S3PublicReadBucketPolicy: "SHS3PublicReadBucketPolicy",
      CertificateManagerCertificate: "SHCertificateManagerCertificate",
      CloudFrontDistribution: "SHCloudFrontDistribution",
      BasicAuthLambda: "SHBasicAuthLambda",
    },
    Options: {
      DomainName: globals.domain,
      // These are the Domains we want to accept connections from
      // (i.e. mydomain.com, www.mydomain.com, etc..)
      Aliases: [globals.domain, `en.${globals.domain}`, `fr.${globals.domain}`],
      WildCardDomain: `*.${globals.domain}`,
      // WithSSL: false,
      // WithPrivateBucket: false,
    },
    Outputs: {
      CFDomainName: "SHCFDomain",
      CFDistributionId: "SHCFDistributionId",
      WebsiteUrl: "SHWebsiteUrl",
      S3BucketSecureUrl: "SHS3BucketSecureUrl",
      S3BucketName: "SHS3BucketName",
    },
  },
} as const;

export default ServerlessConstants;
