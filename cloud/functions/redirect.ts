import ServerlessConstants from "../serverless-constants";

export const hander = (event) => {
  const response = {
    statusCode: 302,
    statusDescription: "Found",
    headers: {
      location: {
        value: `https://${ServerlessConstants.domain}${event.request.uri}`,
      },
    },
  };
  return response;
};
