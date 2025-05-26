import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import * as jose from 'jose';
import open from 'open';
import prompt from 'prompt';

import { OpenIDConfigurationManager, buildAuthorizeURL, codeExchange, pushAuthorizeRequest } from '../src';

const domain = 'criipto-oidc-test.criipto.io';
const client_id = 'urn:my:application:identifier:374100';
const redirect_uri = 'https://jwt.io/';

(async () => {
  const privateKey = await fs.readFile(path.join(__dirname, 'key.pem'), 'utf-8').then(v => jose.importPKCS8(v, 'RS256'));
  const openIDConfigurationManager = new OpenIDConfigurationManager(`https://${domain}`, client_id);
  const openIDConfiguration = await openIDConfigurationManager.fetch();

  const jwt = await new jose.SignJWT({ 'sub': openIDConfiguration.client_id })
    .setProtectedHeader({ alg: 'RS256', kid: '1' })
    .setIssuedAt()
    .setIssuer(openIDConfiguration.client_id)
    .setAudience(openIDConfiguration.issuer)
    .setExpirationTime('5m')
    .sign(privateKey);

  const {request_uri} = await pushAuthorizeRequest(openIDConfiguration, {
    request: {
      redirect_uri,
      response_mode: 'query',
      response_type: 'code',
      scope: 'openid',
      acr_values: 'urn:grn:authn:mock',
      prompt: 'login'
    },
    authentication: {
      client_assertion: jwt
    }
  });

  const authorizeUrl = buildAuthorizeURL(openIDConfiguration, {
    request_uri
  });
  await open(authorizeUrl.href);

  const resultUrl = await prompt.get(['resultUrl']).then(r => r['resultUrl']);
  const code = new URL(resultUrl as string).searchParams.get('code');
  assert(code?.length, `expected non-empty code in '${resultUrl}'`);

  const result = await codeExchange(openIDConfiguration, {
    code,
    redirect_uri,
    client_assertion: jwt
  });
  
  if ("error" in result) {
    throw new Error(JSON.stringify(result.error));
  }
  
  console.log(result.id_token);
})().catch(err => {
  console.error(err);
  process.exit(1);
});