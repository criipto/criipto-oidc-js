# criipto-oidc-js

## Implementing a simple client-secret based flow

```js
// Setup metadata fetching
const configurationManager = new OpenIDConfigurationManager(
  'https://{{YOUR_CRIIPTO_DOMAIN}}',
  '{{YOUR_CRIIPTO_CLIENT_ID}}'
);
const configuration = await configurationManager.fetch();

// Build authorize url
const authorizeUrl = buildAuthorizeURL(
  configuration,
  {
    redirect_uri: 'https://yourdomain/oauth2/callback',
    scope: `openid`,
    response_mode: 'query',
    response_type: 'code',
    /** set to a specific acr_values to request a specific eID */
    acr_values: undefined
  }
);

// Redirect users browser to authorize url
// Exactly how would depend on your platform
// ...
// After user has logged in they are returned
// to your 'redirect_uri' with either
// a 'code' or a 'error' query parameter
const queryParams = {/*...*/}
const {id_token} = await codeExchange(configuration, {
  code: queryParams.code,
  redirect_uri: 'https://yourdomain/oauth2/callback',,
  client_secret: '{{YOUR_CRIIPTO_CLIENT_SECRET}}'
});

// id_token is a JWT containg data based on the chosen
// authentication option, see https://docs.criipto.com/verify/getting-started/token-contents/
```
