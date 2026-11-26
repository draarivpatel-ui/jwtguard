import test from 'node:test';
import assert from 'node:assert/strict';
import {
  esm, cjs, APIs, NOW, HS256_SECRET, signed, verified, expectCode
} from './helpers.mjs';

const verify = (token, options = {}) => esm.verifyJwt(token, HS256_SECRET,
  { algorithms: ['HS256'], now: NOW, ...options });

test('exp is required by default', (t) => {
  const token = signed({ sub: 'x' }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token), 'ERR_JWTGUARD_MISSING_CLAIM');
  assert.equal(verify(token, { requiredClaims: [] }).sub, 'x');
  assert.equal(verify(token, { requiredClaims: ['sub'] }).sub, 'x');
});

test('expired tokens are rejected', (t) => {
  const token = signed({ exp: NOW - 1 }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token), 'ERR_JWTGUARD_EXPIRED');
});

test('token at the exact exp boundary is rejected', (t) => {
  const token = signed({ exp: NOW }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token), 'ERR_JWTGUARD_EXPIRED');
});

test('clockToleranceSeconds allows small expiry skew', () => {
  const token = signed({ exp: NOW - 5 }, 'HS256', HS256_SECRET);
  assert.equal(verify(token, { clockToleranceSeconds: 6 }).exp, NOW - 5);
});

test('clockToleranceSeconds does not rescue far-expired tokens', (t) => {
  const token = signed({ exp: NOW - 100 }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token, { clockToleranceSeconds: 5 }), 'ERR_JWTGUARD_EXPIRED');
});

test('nbf in the future is rejected and tolerance allows small skew', (t) => {
  const token = signed({ exp: NOW + 100, nbf: NOW + 30 }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token), 'ERR_JWTGUARD_NOT_ACTIVE');
  assert.equal(verify(token, { clockToleranceSeconds: 30 }).nbf, NOW + 30);
});

test('nbf at the current second is active', () => {
  const token = signed({ exp: NOW + 100, nbf: NOW }, 'HS256', HS256_SECRET);
  assert.equal(verify(token).nbf, NOW);
});

test('iat in the future is rejected', (t) => {
  const signedToken = esm.signJwt({ exp: NOW + 10 }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW + 20 });
  expectCode(t, () => esm.verifyJwt(signedToken, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_INVALID_IAT');
});

test('clockToleranceSeconds covers iat skew', () => {
  const token = esm.signJwt({ exp: NOW + 10 }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW + 3 });
  assert.equal(esm.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW, clockToleranceSeconds: 3 }).iat, NOW + 3);
});

test('maxAgeSeconds enforces token freshness', (t) => {
  const token = signed({ exp: NOW + 1000 }, 'HS256', HS256_SECRET);
  assert.equal(verify(token, { maxAgeSeconds: 1 }).exp, NOW + 1000);
  expectCode(t, () => esm.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW + 10, maxAgeSeconds: 5 }), 'ERR_JWTGUARD_EXPIRED');
});

test('issuer must match a string or array allowlist', (t) => {
  const token = signed({ exp: NOW + 10, iss: 'https://trusted.example' }, 'HS256', HS256_SECRET);
  assert.equal(verify(token, { issuer: 'https://trusted.example' }).iss, 'https://trusted.example');
  assert.equal(verify(token, { issuer: ['https://other.example', 'https://trusted.example'] }).iss,
    'https://trusted.example');
  expectCode(t, () => verify(token, { issuer: 'https://evil.example' }),
    'ERR_JWTGUARD_ISSUER_MISMATCH');
  expectCode(t, () => verify(token, { issuer: ['https://evil.example'] }),
    'ERR_JWTGUARD_ISSUER_MISMATCH');
});

test('audience must match a string or array form', (t) => {
  const single = signed({ exp: NOW + 10, aud: 'api' }, 'HS256', HS256_SECRET);
  const multiple = signed({ exp: NOW + 10, aud: ['api', 'web'] }, 'HS256', HS256_SECRET);
  assert.equal(verify(single, { audience: 'api' }).aud, 'api');
  assert.equal(verify(single, { audience: ['api', 'other'] }).aud, 'api');
  assert.equal(verify(multiple, { audience: 'web' }).aud[1], 'web');
  expectCode(t, () => verify(single, { audience: 'other' }), 'ERR_JWTGUARD_AUDIENCE_MISMATCH');
  expectCode(t, () => verify(multiple, { audience: 'admin' }), 'ERR_JWTGUARD_AUDIENCE_MISMATCH');
});

test('sub and jti must match exactly', (t) => {
  const token = signed({ exp: NOW + 10, sub: 'user-1', jti: 'token-1' }, 'HS256', HS256_SECRET);
  assert.equal(verify(token, { subject: 'user-1', jwtId: 'token-1' }).sub, 'user-1');
  expectCode(t, () => verify(token, { subject: 'user-2' }), 'ERR_JWTGUARD_SUBJECT_MISMATCH');
  expectCode(t, () => verify(token, { jwtId: 'token-2' }), 'ERR_JWTGUARD_JTI_MISMATCH');
});

test('requiredClaims can demand arbitrary claims', (t) => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token, { requiredClaims: ['exp', 'scope'] }),
    'ERR_JWTGUARD_MISSING_CLAIM');
  assert.equal(verify(token, { requiredClaims: ['exp', 'iat'] }).iat, NOW);
});

test('numeric claims must be finite numbers', (t) => {
  for (const claim of ['exp', 'nbf']) {
    const token = signed({ exp: NOW + 10, [claim]: 'not-a-number' }, 'HS256', HS256_SECRET);
    expectCode(t, () => verify(token), 'ERR_JWTGUARD_INVALID_CLAIM');
    const infinite = signed({ exp: NOW + 10, [claim]: Number.POSITIVE_INFINITY },
      'HS256', HS256_SECRET);
    expectCode(t, () => verify(infinite), 'ERR_JWTGUARD_INVALID_CLAIM');
  }
  for (const bad of ['not-a-number', Number.POSITIVE_INFINITY]) {
    const token = signed({ exp: NOW + 10, iat: bad }, 'HS256', HS256_SECRET,
      { noTimestamp: true });
    expectCode(t, () => verify(token), 'ERR_JWTGUARD_INVALID_CLAIM');
  }
});

test('now accepts an injectable function', () => {
  const token = signed({ sub: 'clock', exp: NOW + 10 }, 'HS256', HS256_SECRET);
  let calls = 0;
  const result = esm.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: () => { calls += 1; return NOW; } });
  assert.equal(result.sub, 'clock');
  assert.equal(calls, 1);
});

test('signJwt supports expiresInSeconds and notBeforeSeconds', () => {
  const token = esm.signJwt({ sub: 'x' }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW, expiresInSeconds: 60, notBeforeSeconds: 5 });
  const payload = verify(token, { clockToleranceSeconds: 5 });
  assert.equal(payload.exp, NOW + 60);
  assert.equal(payload.nbf, NOW + 5);
  assert.equal(payload.iat, NOW);
});

test('noTimestamp suppresses iat', () => {
  const token = esm.signJwt({ exp: NOW + 10 }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW, noTimestamp: true });
  assert.equal(verify(token).iat, undefined);
});

test('invalid option values are rejected', (t) => {
  const token = signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET);
  expectCode(t, () => verify(token, { clockToleranceSeconds: -1 }), 'ERR_JWTGUARD_INVALID_OPTION');
  expectCode(t, () => verify(token, { now: 'now' }), 'ERR_JWTGUARD_INVALID_OPTION');
  expectCode(t, () => verify(token, { maxTokenBytes: 0 }), 'ERR_JWTGUARD_INVALID_OPTION');
  expectCode(t, () => verify(token, { requiredClaims: 'exp' }), 'ERR_JWTGUARD_INVALID_OPTION');
  expectCode(t, () => verify(token, { maxAgeSeconds: -1 }), 'ERR_JWTGUARD_INVALID_OPTION');
});

test('payload must be a plain object', (t) => {
  for (const payload of ['string', 42, null, [], undefined]) {
    expectCode(t, () => esm.signJwt(payload, HS256_SECRET, { algorithm: 'HS256' }),
      'ERR_JWTGUARD_INVALID_CLAIM');
  }
});

test('CJS enforces the same claim validation', (t) => {
  const token = cjs.signJwt({ exp: NOW - 10 }, HS256_SECRET,
    { algorithm: 'HS256', now: NOW });
  expectCode(t, () => cjs.verifyJwt(token, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_EXPIRED');
  const missing = cjs.signJwt({}, HS256_SECRET, { algorithm: 'HS256', now: NOW });
  expectCode(t, () => cjs.verifyJwt(missing, HS256_SECRET,
    { algorithms: ['HS256'], now: NOW }), 'ERR_JWTGUARD_MISSING_CLAIM');
});

test('ESM and CJS agree on claim decisions across many cases', () => {
  const tokens = [
    signed({ exp: NOW + 10 }, 'HS256', HS256_SECRET),
    signed({ exp: NOW - 10 }, 'HS256', HS256_SECRET),
    signed({ exp: NOW + 10, nbf: NOW + 100 }, 'HS256', HS256_SECRET),
    signed({ exp: NOW + 10, aud: 'api' }, 'HS256', HS256_SECRET)
  ];
  const optionSets = [
    {}, { audience: 'api' }, { clockToleranceSeconds: 5 }, { requiredClaims: ['sub'] }
  ];
  for (const token of tokens) {
    for (const options of optionSets) {
      const run = (api) => {
        try {
          return { ok: true, value: api.verifyJwt(token, HS256_SECRET,
            { algorithms: ['HS256'], now: NOW, ...options }) };
        } catch (error) {
          return { ok: false, code: error.code };
        }
      };
      assert.deepEqual(run(esm), run(cjs));
    }
  }
});
