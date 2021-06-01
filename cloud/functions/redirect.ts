export const hander = event => {
  const response = {
    statusCode: 302,
    statusDescription: "Found",
    headers: {
      location: {
        value: "https://yamenai.com" + event.request.uri,
      },
    },
  }
  return response
}
