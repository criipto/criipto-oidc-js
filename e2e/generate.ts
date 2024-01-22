import fs from 'node:fs/promises';
import path from 'node:path';
import * as jose from 'jose';

(async () => {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256');

  const jwk = await jose.exportJWK(publicKey);
  const jwks = {keys: [jwk]};

  await fs.writeFile(path.join(__dirname, 'jwks.json'), JSON.stringify(jwks, null, 2));

  const pem = await jose.exportPKCS8(privateKey);
  await fs.writeFile(path.join(__dirname, 'key.pem'), pem);
})().catch(err => {
  console.error(err);
  process.exit(1);
});