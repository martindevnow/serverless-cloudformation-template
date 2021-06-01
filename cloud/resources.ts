import {
  AWS_CertificateManager_Certificate,
  // AWS_CloudFront_Distribution,
  AWS_S3_Bucket,
} from "./aws.types"
import ServerlessConstants from "./serverless-constants"

// Use a CNAME to point your domain to cloudfront address...

export const CloudFront /*: AWS_CloudFront_Distribution */ = {
  Type: "AWS::CloudFront::Distribution",
  Properties: {
    DistributionConfig: {
      Aliases: ServerlessConstants.Hosting.Aliases,
      Origins: [
        {
          DomainName: `${ServerlessConstants.Resources.S3BucketName}.s3-website-${ServerlessConstants.region}.amazonaws.com`,
          Id: `${ServerlessConstants.Resources.S3BucketName}.s3`,
          OriginPath: "",
          ConnectionAttempts: 3,
          ConnectionTimeout: 10,
          CustomOriginConfig: {
            HTTPPort: 80,
            HTTPSPort: 443,
            OriginKeepaliveTimeout: 5,
            OriginProtocolPolicy: "http-only",
            OriginReadTimeout: 30,
            OriginSSLProtocols: ["TLSv1", "TLSv1.1", "TLSv1.2"],
          },
        },
      ],
      OriginGroups: {
        Quantity: 0,
      },
      DefaultCacheBehavior: {
        AllowedMethods: ["HEAD", "GET"],
        CachedMethods: ["HEAD", "GET"],
        Compress: true,
        DefaultTTL: 60,
        ForwardedValues: {
          Cookies: {
            Forward: "none",
          },
          QueryString: true,
        },
        MaxTTL: 300,
        MinTTL: 0,
        SmoothStreaming: false,
        TargetOriginId: `${ServerlessConstants.Resources.S3BucketName}.s3`,
        ViewerProtocolPolicy: "redirect-to-https",
      },
      Comment: "Yamenai Website",
      PriceClass: "PriceClass_All",
      Enabled: true,
      ViewerCertificate: {
        AcmCertificateArn: {
          Ref: ServerlessConstants.ResourceNames.CertificateManagerCertificate,
        },
        MinimumProtocolVersion: "TLSv1.1_2016",
        SslSupportMethod: "sni-only",
      },
      Restrictions: {
        GeoRestriction: {
          RestrictionType: "none",
        },
      },
      HttpVersion: "http2",
      DefaultRootObject: "index.html",
      IPV6Enabled: true,
    },
  },
}

export const CertificateManagerCertificate: AWS_CertificateManager_Certificate = {
  Type: "AWS::CertificateManager::Certificate",
  Properties: {
    DomainName: ServerlessConstants.Hosting.DomainName,
    SubjectAlternativeNames: [
      ServerlessConstants.Hosting.DomainName,
      ServerlessConstants.Hosting.WildCardDomain,
    ],
    DomainValidationOptions: [
      {
        DomainName: ServerlessConstants.Hosting.DomainName,
        ValidationDomain: ServerlessConstants.Hosting.DomainName,
      },
      {
        DomainName: ServerlessConstants.Hosting.WildCardDomain,
        ValidationDomain: ServerlessConstants.Hosting.WildCardDomain,
      },
    ],
    CertificateTransparencyLoggingPreference: "ENABLED",
  },
}

export const S3Bucket: AWS_S3_Bucket = {
  Type: "AWS::S3::Bucket",
  Properties: {
    BucketName: ServerlessConstants.Resources.S3BucketName,
    Tags: [
      { Key: "type", Value: "hosting" },
      { Key: "client", Value: "yamenai" },
    ],
    VersioningConfiguration: {
      Status: "Enabled",
    },
    WebsiteConfiguration: {
      IndexDocument: "index.html",
      ErrorDocument: "404.html",
    },
  },
}

export const Outputs = {
  [ServerlessConstants.ResourceNames.S3Bucket]: {
    Value: {
      Ref: ServerlessConstants.ResourceNames.S3Bucket,
    },
  },
  [ServerlessConstants.ResourceNames.CloudFrontDistribution]: {
    Value: {
      "Fn::GetAtt": [
        ServerlessConstants.ResourceNames.CloudFrontDistribution,
        "DomainName",
      ],
    },
  },
}
