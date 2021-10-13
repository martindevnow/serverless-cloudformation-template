import {
  // AWS_CertificateManager_Certificate,
  // AWS_CloudFront_CloudFrontOriginAccessIdentity,
  AWS_CloudFront_Distribution,
  AWS_S3_Bucket,
  // AWS_S3_BucketPolicy,
} from "../aws.types";
import ServerlessConstants from "../serverless-constants";

// const S3OriginAccessIdentity: AWS_CloudFront_CloudFrontOriginAccessIdentity = {
//   Type: "AWS::CloudFront::CloudFrontOriginAccessIdentity",
//   Properties: {
//     CloudFrontOriginAccessIdentityConfig: {
//       Comment: `${ServerlessConstants.client} S3 CloudFront OAI`,
//     },
//   },
// };

// For use with S3 buckets without public access
// const S3CloudFrontBucketPolicy /* : AWS_S3_BucketPolicy */ = {
//   Type: "AWS::S3::BucketPolicy",
//   Properties: {
//     // Bucket: `{Ref: ServerlessConstants.StaticHosting.Logical.S3Bucket}`,
//     Bucket: { Ref: ServerlessConstants.StaticHosting.Logical.S3Bucket },
//     PolicyDocument: {
//       Statement: [
//         {
//           Action: "s3:Get*",
//           Effect: "Allow",
//           Resource: `arn:aws:s3:::${ServerlessConstants.StaticHosting.Names.S3Bucket}/*`,
//           Principal: {
//             // CanonicalUser: `{"Fn::GetAtt": [ServerlessConstants.StaticHosting.Logical.S3OriginAccessIdentity, "S3CanonicalUserId"]}`,
//             CanonicalUser: {
//               "Fn::GetAtt": [
//                 ServerlessConstants.StaticHosting.Logical
//                   .S3OriginAccessIdentity,
//                 "S3CanonicalUserId",
//               ],
//             },
//           },
//         },
//       ],
//     },
//   },
// };

const S3PublicReadBucketPolicy /* : AWS_S3_BucketPolicy */ = {
  Type: "AWS::S3::BucketPolicy",
  Properties: {
    Bucket: { Ref: ServerlessConstants.StaticHosting.Logical.S3Bucket },
    PolicyDocument: {
      Statement: [
        {
          Sid: "PublicReadForGetBucketObjects",
          Effect: "Allow",
          Action: "s3:Get*",
          Resource: `arn:aws:s3:::${ServerlessConstants.StaticHosting.Names.S3Bucket}/*`,
          Principal: "*",
        },
      ],
    },
  },
};

const CloudFront: AWS_CloudFront_Distribution = {
  Type: "AWS::CloudFront::Distribution",
  Properties: {
    DistributionConfig: {
      // Aliases: [...ServerlessConstants.StaticHosting.Options.Aliases],
      Origins: [
        {
          Id: `${ServerlessConstants.StaticHosting.Names.S3Bucket}.s3`,
          DomainName: `${ServerlessConstants.StaticHosting.Names.S3Bucket}.s3.amazonaws.com`,
          CustomOriginConfig: {
            HTTPPort: 80,
            HTTPSPort: 443,
            OriginProtocolPolicy: "http-only",
          },

          // For use with S3 with no public access
          // S3OriginConfig: {
          //   OriginAccessIdentity: {
          //     "Fn::Join": [
          //       "",
          //       [
          //         "origin-access-identity/cloudfront/",
          //         {
          //           Ref: ServerlessConstants.StaticHosting.Logical
          //             .S3OriginAccessIdentity,
          //         },
          //       ],
          //     ],
          //   },
          // },
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
        TargetOriginId: `${ServerlessConstants.StaticHosting.Names.S3Bucket}.s3`,
        ViewerProtocolPolicy: "redirect-to-https",
      },
      Comment: `${ServerlessConstants.project} Static Hosting`,
      PriceClass: "PriceClass_100",
      Enabled: true,
      ViewerCertificate: {
        CloudFrontDefaultCertificate: true,
      },
      // ViewerCertificate: {
      //   AcmCertificateArn: {
      //     Ref: ServerlessConstants.StaticHosting.Logical
      //       .CertificateManagerCertificate,
      //   },
      //   MinimumProtocolVersion: "TLSv1.1_2016",
      //   SslSupportMethod: "sni-only",
      // },
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
};

// const CertificateManagerCertificate: AWS_CertificateManager_Certificate = {
//   Type: "AWS::CertificateManager::Certificate",
//   Properties: {
//     DomainName: ServerlessConstants.StaticHosting.Options.DomainName,
//     SubjectAlternativeNames: [
//       ServerlessConstants.StaticHosting.Options.DomainName,
//       ServerlessConstants.StaticHosting.Options.WildCardDomain,
//     ],
//     DomainValidationOptions: [
//       {
//         DomainName: ServerlessConstants.StaticHosting.Options.DomainName,
//         ValidationDomain: ServerlessConstants.StaticHosting.Options.DomainName,
//       },
//       {
//         DomainName: ServerlessConstants.StaticHosting.Options.WildCardDomain,
//         ValidationDomain:
//           ServerlessConstants.StaticHosting.Options.WildCardDomain,
//       },
//     ],
//     CertificateTransparencyLoggingPreference: "ENABLED",
//   },
// };

const S3Bucket: AWS_S3_Bucket = {
  Type: "AWS::S3::Bucket",
  Properties: {
    BucketName: ServerlessConstants.StaticHosting.Names.S3Bucket,
    Tags: [
      { Key: "type", Value: "hosting" },
      { Key: "client", Value: ServerlessConstants.client },
    ],
    VersioningConfiguration: {
      Status: "Enabled",
    },
    WebsiteConfiguration: {
      IndexDocument: "index.html",
      ErrorDocument: "404.html",
    },
  },
};

export const Resources = {
  [ServerlessConstants.StaticHosting.Logical
    .CloudFrontDistribution]: CloudFront,
  [ServerlessConstants.StaticHosting.Logical.S3Bucket]: S3Bucket,
  [ServerlessConstants.StaticHosting.Logical
    .S3PublicReadBucketPolicy]: S3PublicReadBucketPolicy,

  // Enable for Only CloudFront to talk to S3 bucket
  // However: https://www.gatsbyjs.com/docs/how-to/previews-deploys-hosting/deploying-to-s3-cloudfront/#setting-up-cloudfront
  // [ServerlessConstants.StaticHosting.Logical.S3CloudFrontBucketPolicy]:
  //   S3CloudFrontBucketPolicy,
  // [ServerlessConstants.StaticHosting.Logical.S3OriginAccessIdentity]:
  //   S3OriginAccessIdentity,

  // Used for generating SSL Certificates
  // [ServerlessConstants.StaticHosting.Logical.CertificateManagerCertificate]:
  //   CertificateManagerCertificate,
} as const;

export const Outputs = {
  [ServerlessConstants.StaticHosting.Outputs.S3BucketName]: {
    Description: "SH - S3 bucket name",
    Value: {
      Ref: ServerlessConstants.StaticHosting.Logical.S3Bucket,
    },
  },
  [ServerlessConstants.StaticHosting.Outputs.CFDomainName]: {
    Description: "SH - CloudFront distribution domain name",
    Value: {
      "Fn::GetAtt": [
        ServerlessConstants.StaticHosting.Logical.CloudFrontDistribution,
        "DomainName",
      ],
    },
  },
  [ServerlessConstants.StaticHosting.Outputs.CFDistributionId]: {
    Description: "SH - CloudFront distribution ID",
    Value: {
      Ref: ServerlessConstants.StaticHosting.Logical.CloudFrontDistribution,
    },
  },
  [ServerlessConstants.StaticHosting.Outputs.WebsiteUrl]: {
    Description: "SH - S3 Bucket Url",
    Value: {
      "Fn::GetAtt": [
        ServerlessConstants.StaticHosting.Logical.S3Bucket,
        "WebsiteURL",
      ],
    },
  },
  [ServerlessConstants.StaticHosting.Outputs.S3BucketSecureUrl]: {
    Description: "SH - Name of S3 bucket to hold website content",
    Value: {
      "Fn::Join": [
        "",
        [
          "https://",
          {
            "Fn::GetAtt": [
              ServerlessConstants.StaticHosting.Logical.S3Bucket,
              "DomainName",
            ],
          },
        ],
      ],
    },
  },
} as const;
