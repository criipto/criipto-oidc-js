import path from 'node:path';
import fs from 'node:fs/promises';
import { KeyLike, SignJWT, importPKCS8 } from 'jose';

(async () => {
  const privateKey = await fs.readFile(path.join(__dirname, 'key.pem'), 'utf-8').then(v => importPKCS8(v, 'RS256'));
  const body = new URLSearchParams();

  body.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');

  const jwt = await new SignJWT({ 'sub': 'a6609df9-bc9d-4abe-b57f-f1b14f1ec69b' })
    .setProtectedHeader({ alg: 'RS256', kid: '1' })
    .setIssuedAt()
    .setIssuer('a6609df9-bc9d-4abe-b57f-f1b14f1ec69b')
    .setAudience('https://test.maskinporten.no/')
    .setExpirationTime('2minutes from now')
    .sign(privateKey);
  body.append('assertion', jwt);

  const response = await fetch(`https://test.maskinporten.no/token`, {
    method: 'POST',
    body: body
  });
  const payload = await response.json();
  console.log(payload);
})().catch(err => {
  console.error(err);
  process.exit(1);
});