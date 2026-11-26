import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  esm, cjs, NOW, HS256_SECRET, keys, signed, verified, rawToken,
  expectCode, b64
} from './helpers.mjs';

const header = b64({ alg: 'HS256' });
const payload = b64({ exp: NOW + 100 });

test('base64url padding is rejected', (t) => {
  for (const segment of [header + '=', payload + '=', b64({ alg: 'HS256' }) + '==']) {
    expectCode(t, () => esm.inspectJwtHeader(segment + '.' + payload + '.AA'),
      'ERR_JWTGUARD_INVALID_BASE64URL');
  }
});

test('trailing non-base64url garbage in each segment is rejected', (t) => {
  expectCode(t, () => esm.inspectJwtHeader(header + '!.' + payload + '.AA'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
  expectCode(t, () => esm.inspectJwtHeader(header + '.' + payload + '+.AA'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
  expectCode(t, () => esm.inspectJwtHeader(header + '.' + payload + '.AA\n'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
  expectCode(t, () => esm.inspectJwtHeader(header + '.' + payload + '.AA.'),
    'ERR_JWTGUARD_MALFORMED_TOKEN');
});

test('non-canonical base64url encodings are rejected', (t) => {
  const canonical = Buffer.from('{"alg":"HS256"}');
  const encoded = canonical.toString('base64url');
  const alternate = canonical.toString('base64').replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/=+$/, '');
  assert.equal(alternate, encoded);
  const padded = encoded + '===';
  expectCode(t, () => esm.inspectJwtHeader(padded + '.' + payload + '.AA'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
});

test('base64url standard-alphabet characters are rejected', (t) => {
  expectCode(t, () => esm.inspectJwtHeader('eyJhbGc+/.' + payload + '.AA'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
});

test('empty segments are rejected', (t) => {
  for (const token of ['', '..', '.' + payload + '.AA', header + '..AA', header + '.' + payload + '.']) {
    expectCode(t, () => esm.inspectJwtHeader(token), 'ERR_JWTGUARD_MALFORMED_TOKEN');
  }
});

test('segment count other than three is rejected', (t) => {
  for (const token of ['abc', 'a.b', 'a.b.c.d', 'a.b.c.d.e']) {
    expectCode(t, () => esm.inspectJwtHeader(token), 'ERR_JWTGUARD_MALFORMED_TOKEN');
  }
});

test('valid tokens decode to the original JSON through decodeJwtUnsafe', () => {
  const token = signed({ sub: 'x', exp: NOW + 10 }, 'HS256', HS256_SECRET);
  const decoded = esm.decodeJwtUnsafe(token);
  assert.equal(decoded.header.alg, 'HS256');
  assert.equal(decoded.payload.sub, 'x');
  assert.equal(decoded.signingInput, token.split('.').slice(0, 2).join('.'));
  assert.ok(Buffer.isBuffer(decoded.signature));
  assert.equal(decoded.signature.toString('base64url'), token.split('.')[2]);
});

test('decodeJwtUnsafe still refuses malformed structure', (t) => {
  expectCode(t, () => esm.decodeJwtUnsafe('a.b'), 'ERR_JWTGUARD_MALFORMED_TOKEN');
  expectCode(t, () => esm.decodeJwtUnsafe('!!!!.' + payload + '.AA'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
});

test('decodeJwtUnsafe does not enforce header policy or claims', () => {
  const token = rawToken({ alg: 'none', jku: 'https://evil.example' }, { sub: 'x' });
  const decoded = esm.decodeJwtUnsafe(token);
  assert.equal(decoded.header.alg, 'none');
  assert.equal(decoded.header.jku, 'https://evil.example');
});

test('JWS signatures are compared over the exact original encoded bytes', (t) => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  const parts = token.split('.');
  const decodeAsString = (segment) => JSON.parse(Buffer.from(segment, 'base64url').toString());
  assert.equal(decodeAsString(parts[0]).alg, 'HS256');
  const recomputed = crypto.createHmac('sha256', HS256_SECRET)
    .update(parts[0] + '.' + parts[1]).digest('base64url');
  assert.equal(parts[2], recomputed);
  assert.equal(verified(token, 'HS256', HS256_SECRET).exp, NOW + 10);
  expectCode(t, () => esm.verifyJwt(token.replace('.' + parts[2], '.' + recomputed.slice(0, -1) + 'A'),
    HS256_SECRET, { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_SIGNATURE_MISMATCH');
});

test('CJS rejects malleable encodings identically', (t) => {
  expectCode(t, () => cjs.inspectJwtHeader(header + '=.' + payload + '.AA'),
    'ERR_JWTGUARD_INVALID_BASE64URL');
  expectCode(t, () => cjs.inspectJwtHeader('a.b.c.d'), 'ERR_JWTGUARD_MALFORMED_TOKEN');
  expectCode(t, () => cjs.decodeJwtUnsafe(''), 'ERR_JWTGUARD_MALFORMED_TOKEN');
});

test('PEM-shaped string cannot be smuggled as an HMAC secret in CJS', (t) => {
  const pem = keys.rsa.publicKey.export({ type: 'spki', format: 'pem' });
  const token = rawToken({ alg: 'HS256' }, { exp: NOW + 10 });
  expectCode(t, () => cjs.verifyJwt(token, pem, { algorithms: ['HS256'], now: NOW }),
    'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});
