import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  esm, cjs, APIs, NOW, HS256_SECRET, keys, signed, verified, rawToken,
  expectCode, b64
} from './helpers.mjs';

const weakRsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
const ed448 = crypto.generateKeyPairSync('ed448');
const x25519 = crypto.generateKeyPairSync('x25519');
const ecPem = keys.ec.privateKey.export({ type: 'pkcs8', format: 'pem' });
const rsaPem = keys.rsa.privateKey.export({ type: 'pkcs8', format: 'pem' });

function hmacToken(header, payload, secret = HS256_SECRET) {
  const input = b64(header) + '.' + b64(payload);
  const signature = crypto.createHmac('sha256', secret).update(input).digest('base64url');
  return input + '.' + signature;
}

test('DER public keys cannot be reused as HMAC secrets', (t) => {
  const derVariants = [
    keys.rsa.publicKey.export({ type: 'spki', format: 'der' }),
    keys.rsa.publicKey.export({ type: 'pkcs1', format: 'der' }),
    keys.ec.publicKey.export({ type: 'spki', format: 'der' }),
    keys.ed.publicKey.export({ type: 'spki', format: 'der' })
  ];
  for (const der of derVariants) {
    const token = hmacToken({ alg: 'HS256' }, { exp: NOW + 10 }, der);
    expectCode(t, () => esm.verifyJwt(token, der, { algorithms: ['HS256'], now: NOW }),
      'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
    expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, der, { algorithm: 'HS256', now: NOW }),
      'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  }
});

test('DER private keys cannot be reused as HMAC secrets', (t) => {
  const derVariants = [
    keys.rsa.privateKey.export({ type: 'pkcs8', format: 'der' }),
    keys.ec.privateKey.export({ type: 'pkcs8', format: 'der' }),
    keys.ec.privateKey.export({ type: 'sec1', format: 'der' })
  ];
  for (const der of derVariants) {
    expectCode(t, () => esm.verifyJwt(hmacToken({ alg: 'HS256' }, { exp: NOW + 10 }, der), der,
      { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  }
});

test('a normal binary secret that starts with 0x30 is still accepted', () => {
  const secret = Buffer.concat([Buffer.from([0x30]), Buffer.alloc(31, 0x42)]);
  const token = hmacToken({ alg: 'HS256' }, { exp: NOW + 10 }, secret);
  assert.equal(esm.verifyJwt(token, secret, { algorithms: ['HS256'], now: NOW }).exp, NOW + 10);
});

test('Uint8Array key material is accepted everywhere the types allow it', () => {
  const secret = new Uint8Array(Buffer.from(HS256_SECRET));
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  assert.equal(esm.verifyJwt(token, secret, { algorithms: ['HS256'], now: NOW }).exp, NOW + 10);
  const signedWithView = esm.signJwt({ exp: NOW + 10 }, secret, { algorithm: 'HS256', now: NOW });
  assert.equal(verified(signedWithView, 'HS256', HS256_SECRET).exp, NOW + 10);

  const raw = crypto.sign('sha256', Buffer.from('u8'), {
    key: keys.ec.privateKey, dsaEncoding: 'ieee-p1363'
  });
  const der = esm.p1363ToDer(new Uint8Array(raw));
  assert.ok(Buffer.isBuffer(der));
  assert.deepEqual(esm.derToP1363(new Uint8Array(der)), raw);
});

test('signJwt enforces the same key family and curve policy as verifyJwt', (t) => {
  // RS256 labelled token signed with an EC key used to be emitted happily.
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, ecPem,
    { algorithm: 'RS256', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, keys.rsa.privateKey,
    { algorithm: 'ES256', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, keys.ed.privateKey,
    { algorithm: 'ES256', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, ed448.privateKey,
    { algorithm: 'EdDSA', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, x25519.privateKey,
    { algorithm: 'EdDSA', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, keys.ec.privateKey,
    { algorithm: 'EdDSA', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
});

test('valid private keys still sign for every asymmetric algorithm', () => {
  assert.equal(verified(signed({ exp: NOW + 10 }, 'RS256', keys.rsa.privateKey), 'RS256',
    keys.rsa.publicKey).exp, NOW + 10);
  assert.equal(verified(signed({ exp: NOW + 10 }, 'PS256', keys.rsaPss.privateKey), 'PS256',
    keys.rsaPss.publicKey).exp, NOW + 10);
  assert.equal(verified(signed({ exp: NOW + 10 }, 'ES256', keys.ec.privateKey), 'ES256',
    keys.ec.publicKey).exp, NOW + 10);
  assert.equal(verified(signed({ exp: NOW + 10 }, 'EdDSA', keys.ed.privateKey), 'EdDSA',
    keys.ed.publicKey).exp, NOW + 10);
  assert.equal(typeof esm.signJwt({ exp: NOW + 10 }, rsaPem, { algorithm: 'RS256', now: NOW }),
    'string');
});

test('RSA moduli below 2048 bits are rejected on sign and verify', (t) => {
  expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, weakRsa.privateKey,
    { algorithm: 'RS256', now: NOW }), 'ERR_JWTGUARD_WEAK_KEY');
  expectCode(t, () => esm.verifyJwt(hmacToken({ alg: 'RS256' }, { exp: NOW + 10 }),
    weakRsa.publicKey, { algorithms: ['RS256'], now: NOW }), 'ERR_JWTGUARD_WEAK_KEY');
  expectCode(t, () => esm.verifyJwt(hmacToken({ alg: 'PS256' }, { exp: NOW + 10 }),
    weakRsa.publicKey, { algorithms: ['PS256'], now: NOW }), 'ERR_JWTGUARD_WEAK_KEY');
});

test('maxAgeSeconds refuses tokens that omit iat', (t) => {
  const token = hmacToken({ alg: 'HS256' }, { exp: NOW + 300 });
  expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW, maxAgeSeconds: 60 }), 'ERR_JWTGUARD_MISSING_CLAIM');
  const withIat = hmacToken({ alg: 'HS256' }, { exp: NOW + 300, iat: NOW });
  assert.equal(esm.verifyJwt(withIat, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW, maxAgeSeconds: 60 }).iat, NOW);
});

test('maxAgeSeconds validates its own option even without iat', (t) => {
  for (const bad of [-1, Number.NaN, '60', null]) {
    const token = hmacToken({ alg: 'HS256' }, { exp: NOW + 300 });
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
      { algorithms: ['HS256'], now: NOW, maxAgeSeconds: bad }), 'ERR_JWTGUARD_INVALID_OPTION');
  }
});

test('crit may never list a registered header', (t) => {
  for (const crit of [['typ', 'kid'], ['alg'], ['crit'], ['jku']]) {
    const token = rawToken({ alg: 'HS256', crit, typ: 'JWT', kid: 'k1' }, { exp: NOW + 10 });
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
      { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_UNKNOWN_CRIT');
  }
});

test('signJwt refuses to build a header from non-object options', (t) => {
  for (const header of ['kid', ['kid'], 3, true]) {
    expectCode(t, () => esm.signJwt({ exp: NOW + 10 }, HS256_SECRET,
      { algorithm: 'HS256', now: NOW, header }), 'ERR_JWTGUARD_INVALID_OPTION');
  }
});

test('signJwt signs exactly the JSON the caller supplied', (t) => {
  // A toJSON hook used to replace the whole payload after validation.
  expectCode(t, () => esm.signJwt({ sub: 'user', toJSON() { return { sub: 'admin' }; } },
    HS256_SECRET, { algorithm: 'HS256', now: NOW }), 'ERR_JWTGUARD_INVALID_CLAIM');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10, callback() {} }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW }), 'ERR_JWTGUARD_INVALID_CLAIM');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10, nested: { fn() {} } }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW }), 'ERR_JWTGUARD_INVALID_CLAIM');
  const token = esm.signJwt({ sub: 'user', exp: NOW + 10 }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW });
  assert.equal(esm.decodeJwtUnsafe(token).payload.sub, 'user');
});

test('derToP1363 rejects negative and non-minimal DER integers', (t) => {
  const negative = Buffer.from('30240220' + '81' + '11'.repeat(31) + '0200', 'hex');
  expectCode(t, () => esm.derToP1363(negative), 'ERR_JWTGUARD_INVALID_SIGNATURE');
  // 33-byte INTEGER whose leading zero is redundant (next byte has no high bit).
  const redundantZero = Buffer.from('3026' + '0221' + '00' + '7f' + '11'.repeat(31) + '020101', 'hex');
  expectCode(t, () => esm.derToP1363(redundantZero), 'ERR_JWTGUARD_INVALID_SIGNATURE');
  // A real sign pad: 33 bytes, leading zero, next byte has the high bit set.
  const padded = Buffer.from('3045022100' + '88'.repeat(32) + '0220' + '22'.repeat(32), 'hex');
  assert.equal(esm.derToP1363(padded).length, 64);
});

test('decodeJwtUnsafe exposes signature bytes, matching the declared type', () => {
  const decoded = esm.decodeJwtUnsafe(signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET));
  assert.ok(decoded.signature instanceof Uint8Array);
  assert.equal(decoded.signature.length, 32);
});

test('ESM and CJS share every hardening rule', (t) => {
  const der = keys.rsa.publicKey.export({ type: 'spki', format: 'der' });
  for (const api of APIs) {
    expectCode(t, () => api.signJwt({ exp: NOW + 10 }, ecPem,
      { algorithm: 'RS256', now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
    expectCode(t, () => api.signJwt({ exp: NOW + 10 }, weakRsa.privateKey,
      { algorithm: 'RS256', now: NOW }), 'ERR_JWTGUARD_WEAK_KEY');
    expectCode(t, () => api.verifyJwt(hmacToken({ alg: 'HS256' }, { exp: NOW + 10 }), der,
      { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_KEY_TYPE_MISMATCH');
    expectCode(t, () => api.verifyJwt(hmacToken({ alg: 'HS256' }, { exp: NOW + 300 }),
      HS256_SECRET, { algorithms: ['HS256'], now: NOW, maxAgeSeconds: 60 }),
    'ERR_JWTGUARD_MISSING_CLAIM');
  }
  expectCode(t, () => cjs.derToP1363(Buffer.from('30240220' + '81' + '11'.repeat(31) +
    '0200', 'hex')), 'ERR_JWTGUARD_INVALID_SIGNATURE');
});
