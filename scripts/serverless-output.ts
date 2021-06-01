/* eslint-disable @typescript-eslint/no-unused-vars */
// This is a hook, made possible by the `serverless-plugin-output` plugin
// Docs: https://www.serverless.com/plugins/serverless-stack-output
/**
 *
 * @param data outputs of the CloudFormation stack
 * @param _serverless a massive object, but importantly, it contains the serverless configuration as JSON
 *    This can be used to get the current stage, among other things:
 *    ie.) `serverless.service.provider.stage`
 *    This can then be used in CI to trigger outgoing notifications, events, webhooks, etc
 * @param _options I *believe* these are the CLI options passed to the `serverless` command
 */
export const handler = (data: Outputs, _serverless, _options) => {
  // Do something in CI here if you want
  console.log("Received Stack Output", data)
}

// Most of these outputs are controlled by Serverless Framework
// But we can specify outputs in the `resources` section of `serverless.ts`
export interface Outputs {
  VerifyAuthChallengeResponseLambdaFunctionQualifiedArn: string
  UserPoolClientId: string
  UserPoolId: string
  ExampleLambdaFunctionQualifiedArn: string
  DefineAuthChallengeLambdaFunctionQualifiedArn: string
  PreSignUpLambdaFunctionQualifiedArn: string
  PostAuthenticationLambdaFunctionQualifiedArn: string
  HttpApiId: string
  CreateAuthChallengeLambdaFunctionQualifiedArn: string
  ServerlessDeploymentBucketName: string
  HttpApiUrl: string
}
