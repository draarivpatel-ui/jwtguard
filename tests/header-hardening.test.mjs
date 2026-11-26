import test from 'node:test';
import assert from 'node:assert/strict';
import {
  esm, cjs, APIs, NOW, HS256_SECRET, signed, verified, rawToken,
  expectCode, b64
} from './helpers.mjs';

test('inspectJwtHeader parses a header without verifying', () => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  assert.equal(esm.inspectJwtHeader(token).alg, 'HS256');
  assert.equal(esm.inspectJwtHeader(token, { enforcePolicy: true }).typ, 'JWT');
});

for (const header of ['jku', 'x5u', 'jwk', 'x5c']) {
  test('dangerous header ' + header + ' is rejected by default', (t) => {
    const token = rawToken({ alg: 'HS256', [header]: 'https://evil.example/keys' },
      { exp: NOW + 10 });
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
      { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_DANGEROUS_HEADER');
    expectCode(t, () => esm.inspectJwtHeader(token, { enforcePolicy: true }),
      'ERR_JWTGUARD_DANGEROUS_HEADER');
  });

  test('dangerous header ' + header + ' works only when explicitly allowlisted', () => {
    const token = rawToken({ alg: 'HS256', [header]: 'https://trusted.example/keys' },
      { exp: NOW + 10 });
    const headerResult = esm.inspectJwtHeader(token, {
      enforcePolicy: true, allowDangerousHeaders: [header]
    });
    assert.equal(headerResult[header], 'https://trusted.example/keys');
  });
}

test('allowDangerousHeaders validates its input', (t) => {
  for (const bad of ['jku', ['bogus'], [42], {}]) {
    expectCode(t, () => esm.verifyJwt(signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET),
      HS256_SECRET, { algorithms: ['HS256'], now: NOW, allowDangerousHeaders: bad }),
    'ERR_JWTGUARD_INVALID_OPTION');
  }
});

const BAD_KIDS = [
  '../../etc/passwd', 'a/b', '..\\windows\\system32', 'key\u0000null', 'key\nheader',
  "key' OR '1'='1", 'key"; DROP TABLE keys;--', 'foo%2e%2e%2fbar', 'a/*b*/c', 42
];

for (const kid of BAD_KIDS) {
  test('rejects unsafe kid: ' + JSON.stringify(kid), (t) => {
    const token = rawToken({ alg: 'HS256', kid }, { exp: NOW + 10 });
    expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
      { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_INVALID_KID');
  });
}

test('accepts a normal opaque kid', () => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET,
    { header: { kid: 'key-2026-11' } });
  assert.equal(verified(token, 'HS256', HS256_SECRET).exp, NOW + 10);
  assert.equal(esm.inspectJwtHeader(token, { enforcePolicy: true }).kid, 'key-2026-11');
});

test('rejects malformed kid types', (t) => {
  for (const kid of [null, 42, {}, [], '']) {
    const token = rawToken({ alg: 'HS256', kid }, { exp: NOW + 10 });
    expectCode(t, () => esm.inspectJwtHeader(token, { enforcePolicy: true }),
      'ERR_JWTGUARD_INVALID_KID');
  }
});

test('unknown crit header is rejected', (t) => {
  const token = rawToken({ alg: 'HS256', crit: ['exp'] }, { exp: NOW + 10 });
  expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_UNKNOWN_CRIT');
});

test('crit must be a non-empty array of unique strings', (t) => {
  for (const crit of ['alg', [], ['alg', 'alg'], [42], null, {}]) {
    const token = rawToken({ alg: 'HS256', crit }, { exp: NOW + 10 });
    expectCode(t, () => esm.inspectJwtHeader(token, { enforcePolicy: true }),
      'ERR_JWTGUARD_UNKNOWN_CRIT');
  }
});

test('crit may not name an RFC 7515 registered header', (t) => {
  // RFC 7515 section 4.1.11: crit MUST NOT list headers defined by the JWS or
  // JWA specifications. The library implements no crit extensions, so any
  // crit array is rejected.
  for (const crit of [['typ', 'kid'], ['alg'], ['crit']]) {
    const token = rawToken({ alg: 'HS256', crit, typ: 'JWT', kid: 'k1' }, { exp: NOW + 10 });
    expectCode(t, () => esm.inspectJwtHeader(token, { enforcePolicy: true }),
      'ERR_JWTGUARD_UNKNOWN_CRIT');
  }
});

test('duplicate JSON keys in header or payload are rejected', (t) => {
  const payload = b64({ exp: NOW + 10 });
  const dupHeader = Buffer.from('{"alg":"HS256","alg":"RS256"}').toString('base64url');
  expectCode(t, () => esm.verifyJwt(dupHeader + '.' + payload + '.AA', HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_DUPLICATE_JSON_KEY');

  const header = b64({ alg: 'HS256' });
  const dupPayload = Buffer.from('{"exp":' + (NOW + 10) + ',"exp":' + (NOW + 9999) + '}')
    .toString('base64url');
  expectCode(t, () => esm.verifyJwt(header + '.' + dupPayload + '.AA', HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_DUPLICATE_JSON_KEY');
});

test('duplicate keys hidden behind JSON escapes are still rejected', (t) => {
  const payload = b64({ exp: NOW + 10 });
  const header = Buffer.from('{"alg":"HS256","\\u0061lg":"RS256"}').toString('base64url');
  expectCode(t, () => esm.verifyJwt(header + '.' + payload + '.AA', HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_DUPLICATE_JSON_KEY');
});

test('prototype pollution keys are rejected in header and payload', (t) => {
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', [key]: { polluted: true } }))
      .toString('base64url');
    expectCode(t, () => esm.verifyJwt(header + '.' + b64({ exp: NOW + 10 }) + '.AA',
      HS256_SECRET, { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_UNSAFE_KEY');

    expectCode(t, () => esm.verifyJwt(b64({ alg: 'HS256' }) + '.' +
      Buffer.from(JSON.stringify({ exp: NOW + 10, [key]: { polluted: true } })).toString('base64url') +
      '.AA', HS256_SECRET, { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_UNSAFE_KEY');
  }
  assert.equal({}.polluted, undefined);
});

test('nested prototype pollution keys are rejected', (t) => {
  const payload = b64({ exp: NOW + 10, nested: { deep: { constructor: {} } } });
  expectCode(t, () => esm.verifyJwt(b64({ alg: 'HS256' }) + '.' + payload + '.AA',
    HS256_SECRET, { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_UNSAFE_KEY');
});

test('malformed JSON segments are rejected', (t) => {
  const candidates = [
    Buffer.from('{').toString('base64url'),
    Buffer.from('[]').toString('base64url'),
    Buffer.from('{"alg":"HS256",}').toString('base64url'),
    Buffer.from('{"alg":"HS256"} trailing').toString('base64url')
  ];
  for (const header of candidates) {
    expectCode(t, () => esm.inspectJwtHeader(header + '.' + b64({ exp: NOW + 10 }) + '.AA'),
      'ERR_JWTGUARD_MALFORMED_JSON');
  }
});

test('maxTokenBytes caps oversized tokens', (t) => {
  const token = signed({ exp: NOW + 10, big: 'x'.repeat(200) }, 'HS256', HS256_SECRET);
  expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW, maxTokenBytes: 64 }), 'ERR_JWTGUARD_TOKEN_TOO_LARGE');
  expectCode(t, () => esm.inspectJwtHeader(token, { maxTokenBytes: 64 }),
    'ERR_JWTGUARD_TOKEN_TOO_LARGE');
  expectCode(t, () => esm.signJwt({ exp: NOW + 10, big: 'x'.repeat(200) }, HS256_SECRET,
    { algorithm: 'HS256', maxTokenBytes: 64 }), 'ERR_JWTGUARD_TOKEN_TOO_LARGE');
});

test('deeply nested JSON is rejected', (t) => {
  let value = '1';
  for (let i = 0; i < 110; i += 1) value = '[' + value + ']';
  const payload = Buffer.from('{"exp":' + (NOW + 10) + ',"deep":' + value + '}')
    .toString('base64url');
  expectCode(t, () => esm.verifyJwt(b64({ alg: 'HS256' }) + '.' + payload + '.AA',
    HS256_SECRET, { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_MALFORMED_JSON');
});

test('CJS header hardening matches ESM', (t) => {
  const token = rawToken({ alg: 'HS256', jku: 'https://evil.example' }, { exp: NOW + 10 });
  expectCode(t, () => cjs.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_DANGEROUS_HEADER');
  expectCode(t, () => cjs.verifyJwt(rawToken({ alg: 'HS256', crit: ['unknown'] },
    { exp: NOW + 10 }), HS256_SECRET, { algorithms: ['HS256'], now: NOW }),
  'ERR_JWTGUARD_UNKNOWN_CRIT');
});

test('API surface is identical in ESM and CJS', () => {
  const names = Object.keys(esm).filter((key) => key !== 'default').sort();
  assert.deepEqual(Object.keys(cjs).filter((key) => key !== 'default').sort(), names);
  for (const api of APIs) {
    assert.equal(typeof api.signJwt, 'function');
    assert.equal(typeof api.verifyJwt, 'function');
    assert.equal(typeof api.decodeJwtUnsafe, 'function');
    assert.equal(typeof api.inspectJwtHeader, 'function');
    assert.equal(typeof api.JwtGuardError, 'function');
  }
});
