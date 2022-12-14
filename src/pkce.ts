function base64URLEncode(input : Uint8Array) {
  return window.btoa(String.fromCharCode(...input))
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

export async function generate() : Promise<PKCE> {
  const encoder = new TextEncoder();
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  const code_verifier = base64URLEncode(bytes);
  const code_challenge_method = 'S256';
  const subtle = ((window.crypto as any).webkitSubtle as SubtleCrypto) ?? window.crypto.subtle;

  const buffer = await subtle.digest('SHA-256', encoder.encode(code_verifier));
  const code_challenge = await base64URLEncode(new Uint8Array(buffer));
  return {code_verifier, code_challenge, code_challenge_method};
}