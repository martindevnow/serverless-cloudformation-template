import type { AWS } from "@serverless/typescript";

import * as StaticHosting from "./static-hosting";
import * as GatsbyCloud from "./gatsby-cloud";

const AwsResources: AWS["resources"] = {
  // Parameters: {},
  // Conditions: {},
  Resources: {
    ...StaticHosting.Resources,
    ...GatsbyCloud.Resources,
  },
  Outputs: {
    ...StaticHosting.Outputs,
    ...GatsbyCloud.Outputs,
  },
};

export default AwsResources;
