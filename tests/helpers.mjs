import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const require = createRequire(import.meta.url);
export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const esm = await import('../src/index.mjs');
export const cjs = require(path.join(root, 'cjs', 'index.cjs'));
export const APIs = [esm, cjs];

export const NOW = 1_800_000_000;
export const HS256_SECRET = 'a'.repeat(32);
export const HS384_SECRET = 'b'.repeat(48);
export const HS512_SECRET = 'c'.repeat(64);

export const keys = {
  rsa: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
  rsaPss: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
  ec: crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  ed: crypto.generateKeyPairSync('ed25519')
};

export function b64(value) {
  const text = Buffer.isBuffer(value) ? value.toString('utf8')
    : typeof value === 'string' ? value : JSON.stringify(value);
  return Buffer.from(text, 'utf8').toString('base64url');
}

export function rawToken(header, payload, signature = 'AA') {
  return b64(header) + '.' + b64(payload) + '.' + signature;
}

export function customSign(header, payload, signer, key) {
  const input = b64(header) + '.' + b64(payload);
  return input + '.' + signer(input, key);
}

export function hmacSign(algorithm, secret) {
  const hash = algorithm.toLowerCase().replace('hs', 'sha');
  return (input, key) => crypto.createHmac(hash, key).update(input).digest('base64url');
}

export function expectCode(t, fn, code) {
  let caught;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, 'expected ' + code + ' but nothing was thrown');
  assert.equal(caught.name, 'JwtGuardError', 'expected a JwtGuardError, got ' + caught.name);
  assert.equal(caught.code, code, 'expected ' + code + ' but got ' + caught.code);
}

export function signed(payload, algorithm, key, options = {}) {
  return esm.signJwt(payload, key, { algorithm, now: NOW, ...options });
}

export function verified(token, algorithm, key, options = {}) {
  return esm.verifyJwt(token, key, { algorithms: [algorithm], now: NOW, ...options });
}
