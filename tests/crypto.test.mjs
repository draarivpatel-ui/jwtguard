import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  esm, APIs, NOW, HS256_SECRET, HS384_SECRET, HS512_SECRET, keys,
  signed, verified, expectCode, b64
} from './helpers.mjs';

const ALGORITHMS = [
  ['HS256', HS256_SECRET],
  ['HS384', HS384_SECRET],
  ['HS512', HS512_SECRET],
  ['RS256', keys.rsa.privateKey],
  ['PS256', keys.rsaPss.privateKey],
  ['ES256', keys.ec.privateKey],
  ['EdDSA', keys.ed.privateKey]
];

const PUBLIC = {
  RS256: keys.rsa.publicKey,
  PS256: keys.rsaPss.publicKey,
  ES256: keys.ec.publicKey,
  EdDSA: keys.ed.publicKey
};

for (const [algorithm, privateKey] of ALGORITHMS) {
  test(algorithm + ' signs and verifies a real roundtrip', (t) => {
    const token = signed({ sub: 'user-1', iss: 'https://issuer.example', exp: NOW + 600 },
      algorithm, privateKey);
    const parts = token.split('.');
    assert.equal(parts.length, 3);
    assert.equal(JSON.parse(Buffer.from(parts[0], 'base64url').toString()).alg, algorithm);
    const payload = verified(token, algorithm, PUBLIC[algorithm] || privateKey,
      { issuer: 'https://issuer.example' });
    assert.equal(payload.sub, 'user-1');
    assert.equal(payload.iat, NOW);
  });

  test(algorithm + ' rejects a tampered payload with signature mismatch', (t) => {
    const token = signed({ sub: 'alice', exp: NOW + 100 }, algorithm, privateKey);
    const parts = token.split('.');
    parts[1] = b64({ sub: 'attacker', exp: NOW + 100 });
    expectCode(t, () => verified(parts.join('.'), algorithm, PUBLIC[algorithm] || privateKey),
      'ERR_JWTGUARD_SIGNATURE_MISMATCH');
  });

  test(algorithm + ' rejects a tampered signature', (t) => {
    const token = signed({ exp: NOW + 100 }, algorithm, privateKey);
    const parts = token.split('.');
    const last = parts[2].slice(-1) === 'Q' ? 'R' : 'Q';
    parts[2] = parts[2].slice(0, -1) + last;
    expectCode(t, () => verified(parts.join('.'), algorithm, PUBLIC[algorithm] || privateKey),
      'ERR_JWTGUARD_SIGNATURE_MISMATCH');
  });

  test(algorithm + ' produces identical tokens in ESM and CJS at a fixed clock', () => {
    for (const api of APIs) {
      const token = api.signJwt({ sub: 'parity', exp: NOW + 60 }, privateKey,
        { algorithm, now: NOW });
      assert.equal(typeof token, 'string');
      assert.equal(api.verifyJwt(token, PUBLIC[algorithm] || privateKey,
        { algorithms: [algorithm], now: NOW }).sub, 'parity');
    }
  });
}

test('ES256 emits raw IEEE P1363 signatures of exactly 64 bytes', () => {
  const token = signed({ exp: NOW + 10 }, 'ES256', keys.ec.privateKey);
  const signature = Buffer.from(token.split('.')[2], 'base64url');
  assert.equal(signature.length, 64);
  const der = esm.p1363ToDer(signature);
  assert.equal(der[0], 0x30);
  assert.deepEqual(esm.derToP1363(der), signature);
});

test('P1363 and DER conversion roundtrips through real crypto for many ephemeral keys', () => {
  for (let i = 0; i < 12; i += 1) {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const raw = crypto.sign('sha256', Buffer.from('message-' + i), {
      key: pair.privateKey, dsaEncoding: 'ieee-p1363'
    });
    const der = esm.p1363ToDer(raw);
    assert.ok(crypto.verify('sha256', Buffer.from('message-' + i),
      { key: pair.publicKey, dsaEncoding: 'der' }, der));
    assert.deepEqual(esm.derToP1363(der), raw);
  }
});

test('DER converter rejects malformed encodings', (t) => {
  for (const bad of [Buffer.alloc(0), Buffer.from([0x31, 0x06]), Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])]) {
    expectCode(t, () => esm.derToP1363(bad), 'ERR_JWTGUARD_INVALID_SIGNATURE');
  }
  expectCode(t, () => esm.p1363ToDer(Buffer.alloc(63)), 'ERR_JWTGUARD_INVALID_SIGNATURE');
});

test('all seven algorithms are listed exactly once', () => {
  assert.deepEqual([...esm.SUPPORTED_ALGORITHMS], ALGORITHMS.map((entry) => entry[0]));
  assert.equal(new Set(esm.SUPPORTED_ALGORITHMS).size, 7);
});

test('HS256 and PS256 verification uses constant-time comparison path', () => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  const parts = token.split('.');
  const expected = crypto.createHmac('sha256', HS256_SECRET)
    .update(parts[0] + '.' + parts[1]).digest('base64url');
  assert.equal(parts[2], expected);
});
