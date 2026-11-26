import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  esm, cjs, APIs, NOW, HS256_SECRET, keys, rawToken, customSign, hmacSign,
  signed, verified, expectCode, b64
} from './helpers.mjs';

test('verification requires an explicit algorithms allowlist', (t) => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  for (const options of [undefined, {}, { algorithms: [] }, { algorithms: 'HS256' }]) {
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET, options),
      'ERR_JWTGUARD_ALGORITHMS_REQUIRED');
  }
});

test('allowlist rejects unknown or none entries', (t) => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  for (const algorithms of [['none'], ['HS256', 'none'], ['HS999'], [null], [42]]) {
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET, { algorithms, now: NOW }),
      'ERR_JWTGUARD_INVALID_ALGORITHM');
  }
});

test('a token signed with a disallowed algorithm is rejected even with valid signature', (t) => {
  const token = signed({ exp: NOW + 10 }, 'HS384', 'b'.repeat(48));
  expectCode(t, () => esm.verifyJwt(token, 'b'.repeat(48),
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_INVALID_ALGORITHM');
});

for (const spelling of ['none', 'None', 'NONE', 'nOnE']) {
  test('alg:' + spelling + ' is always rejected', (t) => {
    const token = rawToken({ alg: spelling, typ: 'JWT' }, { sub: 'a', exp: NOW + 10 });
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
      { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_ALG_NONE_FORBIDDEN');
    expectCode(t, () => esm.inspectJwtHeader(token, { enforcePolicy: true }),
      'ERR_JWTGUARD_ALG_NONE_FORBIDDEN');
  });

  test('alg:' + spelling + ' cannot be added to the allowlist', (t) => {
    expectCode(t, () => esm.verifyJwt(rawToken({ alg: spelling }, { exp: NOW + 10 }),
      HS256_SECRET, { algorithms: [spelling], now: NOW }), 'ERR_JWTGUARD_INVALID_ALGORITHM');
  });
}

test('RS256 to HS256 confusion attack with PEM public key as HMAC secret is blocked', (t) => {
  const pem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' });
  const input = b64({ alg: 'HS256', typ: 'JWT' }) + '.' + b64({ sub: 'admin', exp: NOW + 100 });
  const signature = crypto.createHmac('sha256', pem).update(input).digest('base64url');
  const token = input + '.' + signature;
  expectCode(t, () => esm.verifyJwt(token, pem, { algorithms: ['HS256'], now: NOW }),
    'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

test('RS256 to HS256 confusion with KeyObject public key is blocked', (t) => {
  const input = b64({ alg: 'HS256' }) + '.' + b64({ exp: NOW + 100 });
  const signature = crypto.createHmac('sha256',
    keys.rsa.publicKey.export({ type: 'spki', format: 'pem' }))
    .update(input).digest('base64url');
  expectCode(t, () => esm.verifyJwt(input + '.' + signature, keys.rsa.publicKey,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

test('symmetric secret presented to RS256, PS256, ES256 and EdDSA is blocked', (t) => {
  for (const algorithm of ['RS256', 'PS256', 'ES256', 'EdDSA']) {
    const token = rawToken({ alg: algorithm }, { exp: NOW + 10 });
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
      { algorithms: [algorithm], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  }
});

test('asymmetric public key cannot sign an HMAC token', (t) => {
  const pem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' });
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, pem, { algorithm: 'HS256' }),
    'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

test('public key cannot sign an asymmetric token', (t) => {
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, keys.ec.publicKey,
    { algorithm: 'ES256' }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

test('RSA key cannot be used for ES256 and an EC key cannot be used for RS256', (t) => {
  expectCode(t, () => esm.verifyJwt(rawToken({ alg: 'ES256' }, { exp: NOW + 10 }),
    keys.rsa.publicKey, { algorithms: ['ES256'], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => esm.verifyJwt(rawToken({ alg: 'RS256' }, { exp: NOW + 10 }),
    keys.ec.publicKey, { algorithms: ['RS256'], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

test('P-384 key is rejected for ES256', (t) => {
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  expectCode(t, () => esm.verifyJwt(rawToken({ alg: 'ES256' }, { exp: NOW + 10 }),
    p384.publicKey, { algorithms: ['ES256'], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

for (const [algorithm, minimum] of [['HS256', 32], ['HS384', 48], ['HS512', 64]]) {
  test(algorithm + ' rejects secrets shorter than ' + minimum + ' bytes', (t) => {
    for (const length of [0, 1, minimum - 1]) {
      const secret = 'x'.repeat(length);
      expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, secret, { algorithm }),
        'ERR_JWTGUARD_WEAK_SECRET');
      const token = signed({ exp: NOW + 10 }, algorithm, 'a'.repeat(minimum));
      expectCode(t, () => esm.verifyJwt(token, secret,
        { algorithms: [algorithm], now: NOW }), 'ERR_JWTGUARD_WEAK_SECRET');
    }
  });

  test(algorithm + ' accepts a secret of exactly ' + minimum + ' bytes', () => {
    const secret = 'z'.repeat(minimum);
    const token = esm.signJwt({ exp: NOW + 10 }, secret, { algorithm, now: NOW });
    assert.equal(esm.verifyJwt(token, secret, { algorithms: [algorithm], now: NOW }).exp, NOW + 10);
  });
}

test('HMAC secret from a secret KeyObject works when long enough', () => {
  const secret = crypto.createSecretKey(Buffer.alloc(32, 7));
  const token = esm.signJwt({ exp: NOW + 10 }, secret, { algorithm: 'HS256', now: NOW });
  assert.equal(esm.verifyJwt(token, secret, { algorithms: ['HS256'], now: NOW }).exp, NOW + 10);
});

test('CJS enforces the same algorithm-confusion defenses', (t) => {
  const pem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' });
  const token = rawToken({ alg: 'HS256' }, { exp: NOW + 10 }, 'AA');
  expectCode(t, () => cjs.verifyJwt(token, pem, { algorithms: ['HS256'], now: NOW }),
    'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => cjs.verifyJwt(token, HS256_SECRET, { now: NOW }),
    'ERR_JWTGUARD_ALGORITHMS_REQUIRED');
  expectCode(t, () => cjs.verifyJwt(rawToken({ alg: 'NONE' }, { exp: NOW + 10 }), HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_ALG_NONE_FORBIDDEN');
});
