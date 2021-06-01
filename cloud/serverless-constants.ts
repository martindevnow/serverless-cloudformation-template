const globals = {
  client: "Yamenai",
  stage: process.env.STAGE || "dev",
  project: "TestCloudFormation",
} as const

// const ServerlessConstants = {
//   client: globals.client,
//   project: globals.project,
//   stage: globals.stage,
//   region: "us-east-1",
//   tags: {
//     client: globals.client,
//     project: globals.project,
//   },
//   Hosting: {
//     BucketName: `${globals.client.toLocaleLowerCase()}-gatsby-${globals.stage}`,
//   },
//   Resources: {
//     DomainName: process.env.DOMAIN_NAME || "yamenai.com",
//     BucketName: `${globals.client}Gatsby${globals.stage}`,
//     PolicyName: `${globals.client}GatsbyPolicy${globals.stage}`,
//     CertName: `${globals.client}GatsbyCert${globals.stage}`,
//     CloudFrontName: `${globals.client}GatsbyCloudFront${globals.stage}`,
//     DnsResourceName: `${globals.client}DnsResource${globals.stage}`,
//     AliasHostedZoneId: "Z2FDTNDATAQYW2",
//   },
// } as const

export const ServerlessConstants = {
  region: "us-east-1",
  client: globals.client,
  Resources: {
    S3BucketName: "yamenai-2021-website-prod",
  },
  ResourceNames: {
    S3Bucket: "S3Bucket",
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
