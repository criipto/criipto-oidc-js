import { KeyLike, SignJWT } from 'jose';

export { generate as generatePKCE, generatePlatform as generatePlatformPKCE} from './pkce';
export { parseQueryResponse, parseURLResponse } from './response';

import { type OpenIDConfiguration } from './OpenIDConfiguration';
import { ErrorResponse } from './response';
export { OpenIDConfigurationManager, type OpenIDConfiguration } from './OpenIDConfiguration';

export function buildLogoutURL(
  configuration: OpenIDConfiguration,
  options: {
    id_token_hint?: string,
    logout_hint?: string,
    post_logout_redirect_uri?: string,
    state?: string,
    ui_locales?: string
  }
) : URL {
  const url = new URL(configuration.end_session_endpoint);

  for (const [k, v] of Object.entries(options)) {
    if (v === undefined || v === null) continue;
    url.searchParams.set(k, v);
  }
  return url;
}

export type AuthorizeURLOptions = {
  redirect_uri: string;
  response_type: string;
  response_mode: string;
  acr_values?: string | string[];
  code_challenge_method?: string,
  code_challenge?: string
  state?: string;
  login_hint?: string;
  ui_locales?: string;
  scope: string;
  prompt?: string;
  nonce?: string
}

export function buildAuthorizeURL(
  configuration: OpenIDConfiguration,
  options: AuthorizeURLOptions | {request_uri: string}
) {
  const url = new URL(configuration.authorization_endpoint);
  url.searchParams.set('client_id', configuration.client_id);
  if ("request_uri" in options) {
    url.searchParams.set('request_uri', options.request_uri);
  } else {
    url.searchParams.set('scope', options.scope ? options.scope : 'openid');

    for (const [k, v] of Object.entries(options)) {
      if (k === 'acr_values') continue;
      if (v === undefined || v === null) continue;
      url.searchParams.set(k, v as string);
    }

    if (options.acr_values) {
      url.searchParams.set('acr_values', Array.isArray(options.acr_values) ? options.acr_values.join(' ') : options.acr_values);
    }
  }
  return url;
}

export function parseAuthorizeOptionsFromUrl(input: string | URL) : Partial<AuthorizeURLOptions> & {domain: string, client_id: string} {
  const url = typeof input === "string" ? new URL(input) : input;
  const acr_values = url.searchParams.get('acr_values');

  return {
    domain: url.host,
    client_id: url.searchParams.get('client_id')!,
    acr_values: acr_values ? acr_values.split(" ") : undefined,
    redirect_uri: url.searchParams.get('redirect_uri') || undefined,
    response_type: url.searchParams.get('response_type') || undefined,
    response_mode: url.searchParams.get('response_mode') || undefined,
    code_challenge: url.searchParams.get('code_challenge') || undefined,
    code_challenge_method: url.searchParams.get('code_challenge_method') || undefined,
    state: url.searchParams.get('state') || undefined,
    login_hint: url.searchParams.get('login_hint') || undefined,
    ui_locales: url.searchParams.get('ui_locales') || undefined,
    scope: url.searchParams.get('scope') || undefined,
    nonce: url.searchParams.get('nonce') || undefined,
    prompt: url.searchParams.get('prompt') || undefined
  };
}

export async function pushAuthorizeRequest(
  configuration: OpenIDConfiguration,
  options: {
    request: AuthorizeURLOptions,
    authentication: {client_secret: string} | {client_assertion: string} | null,
    fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  }
) : Promise<{request_uri: string}> {
  const fetch = options.fetch ?? globalThis.fetch;
  const url = buildAuthorizeURL(configuration, options.request);
  if (!configuration.pushed_authorization_request_endpoint) throw new Error(`OpenID Provider does not support 'pushed_authorization_request_endpoint'`);
  const body = new URLSearchParams(Object.fromEntries(url.searchParams.entries()));
  if (options.authentication && "client_assertion" in options.authentication) {
    body.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    body.append('client_assertion', options.authentication.client_assertion);
  }
  const response = await fetch(configuration.pushed_authorization_request_endpoint, {
    method: 'POST',
    cache: 'no-store',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(options.authentication && "client_secret" in options.authentication ? {
        Authorization: "Basic " + btoa(`${encodeURIComponent(configuration.client_id)}:${options.authentication.client_secret}`)
      } : {}),
      'cache-control': 'no-cache, no-store, must-revalidate'
    },
    body: body.toString()
  });

  if (response.status >= 400) throw new Error(await response.clone().text());
  const payload = await response.json() as {request_uri: string};
  return payload;
}

export async function codeExchange(
  configuration: OpenIDConfiguration,
  options: {
    code: string,
    redirect_uri: string
    code_verifier: string
    fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  } | {
    code: string,
    redirect_uri: string
    client_secret: string
    fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  } | {
    code: string
    redirect_uri: string
    signingKey: KeyLike
    fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  } | {
    code: string,
    redirect_uri: string
    code_verifier?: string
    client_assertion: string
    fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  }
) : Promise<{id_token: string, access_token: string} | ErrorResponse> {
  const body = new URLSearchParams();
  const fetch = options.fetch ?? globalThis.fetch;
  
  body.append('grant_type', "authorization_code");
  body.append('code', options.code);
  body.append('client_id', configuration.client_id);
  body.append('redirect_uri', options.redirect_uri);
  if ("code_verifier" in options && options.code_verifier) body.append('code_verifier', options.code_verifier);
  if ("signingKey" in options) {
    body.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');

    const jwt = await new SignJWT({ 'sub': configuration.client_id })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setIssuer(configuration.client_id)
      .setAudience(configuration.issuer)
      .setExpirationTime('5m')
      .sign(options.signingKey);
    body.append('client_assertion', jwt);
  }
  if ("client_assertion" in options) {
    body.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    body.append('client_assertion', options.client_assertion);
  }

  const response = await fetch(configuration.token_endpoint, {
    method: 'POST',
    cache: 'no-store',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...("client_secret" in options ? {
        Authorization: "Basic " + btoa(`${encodeURIComponent(configuration.client_id)}:${options.client_secret}`)
      } : {}),
      'cache-control': 'no-cache, no-store, must-revalidate'
    },
    body: body.toString()
  });

  const payload = await response.json();
  if (payload.error) return {error: payload.error, error_description: payload.error_description};
  return {id_token: payload.id_token, access_token: payload.access_token};
}

export async function userInfo(
  configuration: OpenIDConfiguration,
  accessToken: string,
  options?: {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  }
) : Promise<{[key: string]: string} | ErrorResponse> {
  const fetch = options?.fetch ?? globalThis.fetch;
  const response = await fetch(configuration.userinfo_endpoint, {
    method: 'GET',
    cache: 'no-store',
    redirect: 'manual',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'cache-control': 'no-cache, no-store, must-revalidate'
    },
  });

  const payload = await response.json();
  if (payload.error) return {error: payload.error, error_description: payload.error_description, state: payload.state};
  return payload;
}
