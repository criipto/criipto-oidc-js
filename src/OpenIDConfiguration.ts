export class OpenIDMetadata {
  issuer: string;
  jwks_uri: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  end_session_endpoint: string;
  response_types_supported: string[];
  response_modes_supported: string[];
  subject_types_supported: string[];
  acr_values_supported: string[];
  id_token_signing_alg_values_supported: string[];
}

export default class OpenIDConfiguration extends OpenIDMetadata {
  authority: string;
  clientID: string

  constructor(authority: string, clientID: string) {
    super();
    this.authority = authority;
    this.clientID = clientID;
  }

  async fetch(): Promise<OpenIDMetadata> {
    const response = await fetch(`${this.authority}/.well-known/openid-configuration?client_id=${this.clientID}`);
    const metadata : OpenIDMetadata = await response.json();
    Object.assign(this, metadata);
    return metadata;
  }
}