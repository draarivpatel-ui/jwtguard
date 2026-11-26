# jwtguard

Zero-dependency hardened JWT/JWS signing and verification for Node.js.

`jwtguard` targets the security gap left by permissive JWT libraries. It never guesses an algorithm from an untrusted token, never accepts `alg: none`, and never lets a public PEM become an HMAC secret.

- Zero runtime dependencies. Only `node:crypto` is used.
- ESM (`src/index.mjs`), CommonJS (`cjs/index.cjs`) and strict TypeScript definitions (`types/index.d.ts`).
- 150+ deterministic tests covering real cryptography and classic JWT CVEs.
- Node.js 18 or newer.

## Install

```sh
npm install jwtguard
```

## Quick start

```js
import { signJwt, verifyJwt } from 'jwtguard';

const secret = 'a'.repeat(32); // HS256 requires at least 32 bytes
const token = signJwt(
  { sub: 'user-123', exp: Math.floor(Date.now() / 1000) + 300 },
  secret,
  { algorithm: 'HS256' }
);

const claims = verifyJwt(token, secret, {
  algorithms: ['HS256'], // mandatory, never inferred from the token
  issuer: 'https://issuer.example',
  audience: 'my-api'
});
```

CommonJS works the same way:

```js
const { signJwt, verifyJwt } = require('jwtguard');
```

## Supported algorithms

| Family | Algorithms | Key material |
| --- | --- | --- |
| HMAC | `HS256`, `HS384`, `HS512` | string or Buffer secret, at least 32, 48 or 64 bytes respectively |
| RSA PKCS#1 v1.5 | `RS256` | RSA private key for signing, RSA public key for verification |
| RSA-PSS | `PS256` | RSA private key for signing, RSA public key for verification |
| ECDSA P-256 | `ES256` | EC private key for signing, EC public key for verification; raw IEEE P1363 signatures |
| Ed25519 | `EdDSA` | Ed25519 private key for signing, Ed25519 public key for verification |

Keys may be PEM strings, Buffers or `crypto.KeyObject` instances. HMAC comparisons use `crypto.timingSafeEqual`.

## API

### `signJwt(payload, key, options)`

Signs a plain-object payload. `options.algorithm` is required. Optional fields:

- `header`: extra registered header claims, such as `kid`.
- `now`: a fixed integer clock in seconds, or a function returning one.
- `expiresInSeconds`, `notBeforeSeconds`: populate `exp` and `nbf`.
- `noTimestamp`: suppress the automatic `iat` claim.
- `maxTokenBytes`: cap the emitted token size, default 16384 bytes.

### `verifyJwt(token, key, options)`

Verifies structure, header policy, signature and claims. `options.algorithms` is required. Optional fields:

- `clockToleranceSeconds`: allowed skew for `exp`, `nbf` and `iat`.
- `requiredClaims`: claim names that must be present. Defaults to `['exp']`.
- `issuer`, `audience`, `subject`, `jwtId`: expected claim values.
- `maxAgeSeconds`: reject tokens older than this relative to `iat`.
- `maxTokenBytes`: cap accepted token size.
- `allowDangerousHeaders`: explicit opt-in list from `jku`, `x5u`, `jwk`, `x5c`.

Returns the verified payload. All failures throw `JwtGuardError` with a typed `code`.

### `decodeJwtUnsafe(token, options?)`

Splits and parses a token without verifying anything. Use only for diagnostics. It still enforces canonical base64url, strict JSON and the token size limit.

### `inspectJwtHeader(token, options?)`

Returns the parsed header without verifying. Set `enforcePolicy: true` to apply the same `crit`, dangerous-header and `kid` checks used by `verifyJwt`.

### `p1363ToDer(signature)` and `derToP1363(signature)`

Convert ES256 signatures between Node's raw IEEE P1363 form and ASN.1 DER form.

### `JwtGuardError`

Every error has a stable `code` such as `ERR_JWTGUARD_EXPIRED`, `ERR_JWTGUARD_KEY_TYPE_MISMATCH` or `ERR_JWTGUARD_DUPLICATE_JSON_KEY`. The full set is exported as `ERROR_CODES`.

## Threat model

`jwtguard` protects the verifier side of a JWS. It assumes the application supplies the correct verification key out of band and does not fetch keys from the token itself.

Defenses included:

- **Algorithm confusion.** The allowlist is mandatory and checked against the header before any key is used. `none` in any casing is always rejected. RSA public keys presented as HMAC secrets are rejected by key-type detection. Symmetric secrets presented to asymmetric algorithms are rejected. RSA, PSS, EC and Ed25519 keys are additionally checked for the correct key family and curve.
- **Weak secrets.** HMAC keys shorter than 32, 48 or 64 bytes are rejected for HS256, HS384 and HS512.
- **Header injection.** `jku`, `x5u`, `jwk` and `x5c` are blocked by default, since honoring them enables remote key injection and SSRF. `kid` is checked for path traversal, control characters, null bytes and SQL-injection patterns. Unknown `crit` headers are rejected as required by RFC 7515.
- **Parser attacks.** Duplicate JSON keys, including escaped duplicates, are rejected before `JSON.parse`. Prototype-pollution keys (`__proto__`, `constructor`, `prototype`) are rejected anywhere in the header or payload. Non-canonical base64url, padding and trailing garbage are rejected. Token size and JSON depth are capped.
- **Claim attacks.** `exp` is required by default. `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, `maxAgeSeconds` and configurable clock tolerance are enforced with an injectable clock for deterministic tests.

Compared with general-purpose JWT libraries that infer the algorithm from the token and accept many header forms by default, `jwtguard` deliberately rejects anything it cannot verify safely. It does not implement JWE encryption, JWKS fetching or key rotation; those belong in separate, audited components. See `GOOD_FIRST_ISSUES.md` for planned adapters.

## Contributing

Run `npm test` before opening a pull request. See `CONTRIBUTING.md` and `GOOD_FIRST_ISSUES.md`.

## License

MIT
