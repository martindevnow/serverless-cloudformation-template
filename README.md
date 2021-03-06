# Cloud Formation Template

This repo is a serverless template for a cloudfront distribution with some bells and whistles.

## Development

This is under development to build something reusable to make it easy to quickly deploy a website to an S3 bucket served by a cloudfront CDN.

## Env

```
# The stage/alias of your environment
STAGE=dev/test/stage/prod/live # etc
```

## External Wiring

### Domain Name

Your domain name will need to have a CNAME record to point any domain or subdomains to this cloudfront url. The cloudfront URL is available in the CloudFront console.

## Pricing:

### Price Class

https://aws.amazon.com/cloudfront/pricing/

## TODO:

- [ ] Optionally attach lambda functions as CloudFront Functions (new)
- [ ] Add the option to have certain subdomains/urls redirect..
- [ ] Make these redirect rules configurable `rule: (request) => null | string`
- [ ] Add the option to add basic auth (username / password ) to the website
- [ ] Make custom auth configurable
- [ ] Make `domain`, `bucketName` etc configurable
