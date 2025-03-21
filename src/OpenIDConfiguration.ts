export type OpenIDConfiguration = {
  client_id: string
  issuer: string
  jwks_uri: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  end_session_endpoint: string
  response_types_supported: string[]
  response_modes_supported: string[]
  subject_types_supported: string[]
  acr_values_supported: string[]
  id_token_signing_alg_values_supported: string[]
}

type CacheEntry<T> = {
  cachedAt: string
  entry: T
}

export class Cache<T> {
  storage: Storage
  lifetimeMs: number

  constructor(storage: Storage, lifetimeMs: number) {
    this.lifetimeMs = lifetimeMs;
    this.storage = storage;
  }

  add(key: string, entry: T) {
    const cacheEntry : CacheEntry<T> = {
      cachedAt: (new Date()).toJSON(),
      entry
    };
    this.storage.setItem(key, JSON.stringify(cacheEntry));
  }
  
  get(key: string) {
    const cacheEntryCandidate = this.storage.getItem(key);
    if (!cacheEntryCandidate) return null;

    const cacheEntry : CacheEntry<T> = JSON.parse(cacheEntryCandidate);
    const cachedAt = new Date(cacheEntry.cachedAt);
    const isExpired = (cachedAt.valueOf() + this.lifetimeMs) >= Date.now();
    if (isExpired) return null;
    return cacheEntry.entry;
  }
}

export class OpenIDConfigurationManager {
  authority: string
  clientID: string
  cache: Cache<OpenIDConfiguration> | undefined
  private _fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

  constructor(authority: string, clientID: string, options?: {
    cacheStorage?: Storage,
    fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  }) {
    if (!authority.startsWith('http')) throw new Error(`OpenIDConfigurationManager authority should start with https://`);
    this.authority = authority;
    this.clientID = clientID;
    this.cache = options?.cacheStorage ? new Cache(options.cacheStorage, 60000) : undefined;
    this._fetch = options?.fetch ?? globalThis.fetch;
  } 

  async fetch(): Promise<OpenIDConfiguration> {
    const url = `${this.authority}/.well-known/openid-configuration?client_id=${this.clientID}`;
    
    const cacheEntry = this.cache?.get(url);
    if (cacheEntry) return cacheEntry;

    const response = await this._fetch(url);
    const metadata : OpenIDConfiguration = await response.json();
    metadata.client_id = this.clientID;

    this.cache?.add(url, metadata);
    return metadata;
  }
}