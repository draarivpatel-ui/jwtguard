# Security policy

## Supported versions

Security fixes are applied to the latest published minor version.

## Reporting a vulnerability

Please report security issues privately through the repository's security advisory form. Include:

- the affected version and runtime,
- a minimal reproducing token or script,
- the impact you believe is possible.

Do not open a public issue for an unpatched vulnerability. You should receive an acknowledgement within seven days.

## What is in scope

- Signature verification bypasses for any supported algorithm.
- Algorithm confusion or key-type confusion.
- Header policy bypasses, including `crit`, `jku`, `x5u`, `jwk`, `x5c` and `kid`.
- JSON or base64url parser differential attacks.
- Claim validation bypasses.
- Timing or denial-of-service issues in the verification path.

## What is out of scope

- Applications that ignore thrown errors or use `decodeJwtUnsafe` to authorize requests.
- Applications that pass attacker-controlled keys to `verifyJwt`.
- JWE encryption, which this library does not implement.
- Social engineering and credential theft.

## Design note

`jwtguard` never fetches keys from a token. Callers must provide trusted key material and an explicit `algorithms` allowlist. If a caller allows dangerous headers via `allowDangerousHeaders`, that caller takes responsibility for validating the values.
