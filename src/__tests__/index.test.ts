import {describe, expect, it, jest, beforeEach} from '@jest/globals';
import { buildAuthorizeURL, codeExchange, userInfo } from '../index';
import type {OpenIDConfiguration} from '../OpenIDConfiguration';

const mockedFetch = jest.fn() as jest.Mocked<typeof fetch>
global.fetch = mockedFetch;

const configuration : OpenIDConfiguration = {
  client_id: `urn:grn:${Math.random().toString()}`,
  issuer: `https://some.authority.com`,
  jwks_uri: `https://some.authority.com/jwks/${Math.random().toString()}`,
  authorization_endpoint: `https://some.authority.com/authorize/${Math.random().toString()}`,
  token_endpoint: `https://some.authority.com/token/${Math.random().toString()}`,
  userinfo_endpoint: `https://some.authority.com/userinfo/${Math.random().toString()}`,
  end_session_endpoint: "",
  response_types_supported: [],
  response_modes_supported: [],
  subject_types_supported: [],
  acr_values_supported: [],
  id_token_signing_alg_values_supported: []
};

describe('codeExchange', () => {
  beforeEach(() => {mockedFetch.mockClear();});

  it('handles successfull PKCE exchange', async () => {
    const code = Math.random().toString();
    const code_verifier = Math.random().toString();
    const redirect_uri = Math.random().toString();
    const id_token = Math.random().toString();
    const access_token = Math.random().toString();

    mockedFetch.mockResolvedValue({
      status: 200,
      json: jest.fn<any>().mockResolvedValue({
        id_token,
        access_token
      })
    } as any);


    const actual = await codeExchange(configuration, {
      code,
      redirect_uri,
      code_verifier
    });

    expect(actual).toStrictEqual({id_token, access_token});
    expect(mockedFetch).toHaveBeenCalledWith(configuration.token_endpoint, {
      cache: 'no-store',
      redirect: 'manual',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        "cache-control": "no-cache, no-store, must-revalidate"
      },
      body: `grant_type=authorization_code&code=${code}&client_id=${encodeURIComponent(configuration.client_id)}&redirect_uri=${redirect_uri}&code_verifier=${code_verifier}`
    });
  });

  it('handles failed PKCE exchange', async () => {
    const code = Math.random().toString();
    const code_verifier = Math.random().toString();
    const redirect_uri = Math.random().toString();
    const error = Math.random().toString();

    mockedFetch.mockResolvedValue({
      status: 200,
      json: jest.fn<any>().mockResolvedValue({
        error
      })
    } as any);


    const actual = await codeExchange(configuration, {
      code,
      redirect_uri,
      code_verifier
    });

    expect(actual).toStrictEqual({error, error_description: undefined});
    expect(mockedFetch).toHaveBeenCalledWith(configuration.token_endpoint, {
      cache: 'no-store',
      redirect: 'manual',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        "cache-control": "no-cache, no-store, must-revalidate"
      },
      body: `grant_type=authorization_code&code=${code}&client_id=${encodeURIComponent(configuration.client_id)}&redirect_uri=${redirect_uri}&code_verifier=${code_verifier}`
    });
  });

  it('handles successfull secret-based code exchange', async () => {
    const code = Math.random().toString();
    const redirect_uri = Math.random().toString();
    const id_token = Math.random().toString();
    const access_token = Math.random().toString();
    const client_secret = Math.random().toString();

    mockedFetch.mockResolvedValue({
      status: 200,
      json: jest.fn<any>().mockResolvedValue({
        id_token,
        access_token
      })
    } as any);


    const actual = await codeExchange(configuration, {
      code,
      redirect_uri,
      client_secret
    });

    expect(actual).toStrictEqual({id_token, access_token});
    expect(mockedFetch).toHaveBeenCalledWith(configuration.token_endpoint, {
      cache: 'no-store',
      redirect: 'manual',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa(`${encodeURIComponent(configuration.client_id)}:${client_secret}`),
        "cache-control": "no-cache, no-store, must-revalidate"
      },
      body: `grant_type=authorization_code&code=${code}&client_id=${encodeURIComponent(configuration.client_id)}&redirect_uri=${redirect_uri}`
    });
  });
});

describe('userInfo', () => {
  beforeEach(() => {mockedFetch.mockClear();});

  const configuration : OpenIDConfiguration = {
    client_id: Math.random().toString(),
    issuer: `https://some.authority.com`,
    jwks_uri: `https://some.authority.com/jwks/${Math.random().toString()}`,
    authorization_endpoint: `https://some.authority.com/authorize/${Math.random().toString()}`,
    token_endpoint: `https://some.authority.com/token/${Math.random().toString()}`,
    userinfo_endpoint: `https://some.authority.com/userinfo/${Math.random().toString()}`,
    end_session_endpoint: "",
    response_types_supported: [],
    response_modes_supported: [],
    subject_types_supported: [],
    acr_values_supported: [],
    id_token_signing_alg_values_supported: []
  };

  it('handles successfull response', async () => {
    const claims = {
      [Math.random().toString()]: Math.random().toString(),
      [Math.random().toString()]: Math.random().toString(),
      [Math.random().toString()]: Math.random().toString(),
    }
    const access_token = Math.random().toString();

    mockedFetch.mockResolvedValue({
      status: 200,
      json: jest.fn<any>().mockResolvedValue(claims)
    } as any);


    const actual = await userInfo(configuration, access_token);

    expect(actual).toStrictEqual(claims);
    expect(mockedFetch).toHaveBeenCalledWith(configuration.userinfo_endpoint, {
      cache: 'no-store',
      redirect: 'manual',
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + access_token,
        "cache-control": "no-cache, no-store, must-revalidate"
      },
    });
  });
});

describe('buildAuthorizeURL', () => {
  it('does not include undefined values', () => {
    const redirect_uri = Math.random().toString();
    const actual = buildAuthorizeURL(configuration, {
      redirect_uri,
      scope: `openid`,
      response_mode: 'query',
      response_type: 'code',
      login_hint: undefined
    });

    expect(actual.href).toEqual(`${configuration.authorization_endpoint}?client_id=${encodeURIComponent(configuration.client_id)}&scope=openid&redirect_uri=${encodeURIComponent(redirect_uri)}&response_mode=query&response_type=code`)
  });

  it('can build signed request', () => {
    const request = Math.random().toString();
    const actual = buildAuthorizeURL(configuration, {
      request
    });

    expect(actual.href).toEqual(`${configuration.authorization_endpoint}?client_id=${encodeURIComponent(configuration.client_id)}&request=${encodeURIComponent(request)}`)
  });

  it('can build PAR request', () => {
    const request_uri = Math.random().toString();
    const actual = buildAuthorizeURL(configuration, {
      request_uri
    });

    expect(actual.href).toEqual(`${configuration.authorization_endpoint}?client_id=${encodeURIComponent(configuration.client_id)}&request_uri=${encodeURIComponent(request_uri)}`)
  });
});