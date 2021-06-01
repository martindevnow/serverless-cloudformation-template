const globals = {
  client: "yamenai",
  stage: process.env.STAGE || "dev",
  project: "blogstarter",
  region: "us-east-1",
} as const

export const ServerlessConstants = {
  region: globals.region,
  client: globals.client,
  Resources: {
    S3BucketName: `yamenai-website-${globals.stage}`,
  },
  ResourceNames: {
    S3Bucket: "S3Bucket",
    S3OriginAccessIdentity: "S3OriginAccessIdentity",
    S3BucketPolicy: "S3BucketPolicy",
    CertificateManagerCertificate: "CertificateManagerCertificate",
    CloudFrontDistribution: "CloudFrontDistribution",
  },
  Hosting: {
    DomainName: "yamenai.com",
    // These are the Domains we want to accept connections from
    // (i.e. mydomain.com, www.mydomain.com, etc..)
    Aliases: ["yamenai.com", "www.yamenai.com", "www2.yamenai.com"],
    WildCardDomain: "*.yamenai.com",
  },
} as const

export default ServerlessConstants
