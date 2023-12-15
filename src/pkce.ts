function base64URLEncode(input : Uint8Array) {
  return btoa(String.fromCharCode(...input))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
}

export interface PKCE {
  code_verifier: string
  code_challenge: string
  code_challenge_method: string
}
export type PKCEPublicPart = Omit<PKCE, 'code_verifier'>;

interface PartialCrypto {
  getRandomValues<T extends Uint8Array>(t: T): T,
  subtle: {
    digest(algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer>
  }
}

function browserCrypto() : PartialCrypto {
  return {
    getRandomValues: crypto.getRandomValues.bind(crypto),
    subtle: ((crypto as any).webkitSubtle as SubtleCrypto) ?? crypto.subtle
  }
}

export async function generatePlatform(crypto: PartialCrypto) : Promise<PKCE> {
  const encoder = new TextEncoder();
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  if (bytes === null || bytes.byteLength === 0) throw new Error('crypto.getRandomValues returned null/no bytes');

  const code_verifier = base64URLEncode(bytes);
  const code_challenge_method = 'S256';
  const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(code_verifier));
  const code_challenge = base64URLEncode(new Uint8Array(buffer));

  if (!code_verifier?.length) throw new Error('Unable to generate PKCE, code_verifier blank');
  if (!code_challenge?.length) throw new Error('Unable to generate PKCE, code_challenge blank');

  return {code_verifier, code_challenge, code_challenge_method};
}

export function generate() : Promise<PKCE> {
  const crypto = browserCrypto();
  return generatePlatform(crypto);
}