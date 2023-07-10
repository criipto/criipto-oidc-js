import {describe, expect, it, jest, beforeEach} from '@jest/globals';
import crypto from 'node:crypto';
import { generatePlatformPKCE } from '..';

describe('pkce', () => {
  it('should generate verifier and challenge', async () => {
    const actual = await generatePlatformPKCE(crypto.webcrypto);

    expect(actual.code_challenge).toBeDefined();
    expect(actual.code_challenge_method).toBeDefined();
    expect(actual.code_verifier).toBeDefined();
  });
});