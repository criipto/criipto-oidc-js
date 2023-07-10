# criipto-oidc-js

## PKCE with Node.js

```js
import crypto from 'node:crypto';

const pkce = await generatePlatformPKCE(crypto.webcrypto);
// pkce.code_verifier, pkce.code_challenge, pkce.code_challenge_method
```