import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { signJwt, verifyJwt } from '../src/index.mjs';

const SECRET = 'x'.repeat(32);
const NOW = 1_800_000_000;
const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

function verifyHs256(token) {
  return verifyJwt(token, SECRET, { algorithms: ['HS256'], now: NOW });
}

function sign(payload) {
  return signJwt(payload, SECRET, { algorithm: 'HS256', now: NOW });
}

function b64json(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function assertJwtRejected(token) {
  assert.throws(
    () => verifyHs256(token),
    (error) => error && error.name === 'JwtGuardError',
  );
}

const subjectArbitrary = fc.string({
  unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'),
  minLength: 1,
  maxLength: 40,
});
const textArbitrary = fc.string({ maxLength: 80 });
const b64Mutation = fc.constantFrom(...(B64URL_ALPHABET + '.!'));

function payloadFor(subject, text) {
  return { sub: subject, note: text, exp: NOW + 3600 };
}

test('mutated signed JWTs never verify', () => {
  fc.assert(
    fc.property(
      subjectArbitrary,
      textArbitrary,
      fc.integer({ min: 0, max: 2 }),
      fc.integer({ min: 0, max: 4096 }),
      b64Mutation,
      (subject, note, segmentIndex, position, replacement) => {
        const token = sign(payloadFor(subject, note));
        assert.equal(verifyHs256(token).sub, subject);

        const parts = token.split('.');
        const index = position % parts[segmentIndex].length;
        fc.pre(parts[segmentIndex][index] !== replacement);
        parts[segmentIndex] = parts[segmentIndex].slice(0, index) + replacement + parts[segmentIndex].slice(index + 1);
        assertJwtRejected(parts.join('.'));
      },
    ),
    { seed: 20261127, numRuns: 200, endOnFailure: true },
  );
});

test('payload substitution with the original signature never verifies', () => {
  fc.assert(
    fc.property(subjectArbitrary, subjectArbitrary, textArbitrary, (victimSubject, attackerSubject, note) => {
      fc.pre(victimSubject !== attackerSubject);
      const victimToken = sign(payloadFor(victimSubject, note));
      const parts = victimToken.split('.');
      parts[1] = b64json(payloadFor(attackerSubject, note));
      const forged = parts.join('.');

      assert.equal(verifyHs256(victimToken).sub, victimSubject);
      assert.throws(
        () => verifyHs256(forged),
        (error) => error && error.code === 'ERR_JWTGUARD_SIGNATURE_MISMATCH',
      );
    }),
    { seed: 20261128, numRuns: 150, endOnFailure: true },
  );
});

test('none-algorithm JWTs always fail regardless of spelling or payload', () => {
  const algSpelling = fc.constantFrom('none', 'None', 'NONE', 'nOnE');
  const signature = fc.constantFrom('AA', 'AAAA');
  fc.assert(
    fc.property(algSpelling, subjectArbitrary, textArbitrary, signature, (alg, subject, note, forgedSignature) => {
      const token = b64json({ alg, typ: 'JWT' }) + '.' + b64json(payloadFor(subject, note)) + '.' + forgedSignature;
      assert.throws(
        () => verifyHs256(token),
        (error) => error && error.code === 'ERR_JWTGUARD_ALG_NONE_FORBIDDEN',
      );
    }),
    { seed: 20261129, numRuns: 150, endOnFailure: true },
  );
});
