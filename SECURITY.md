# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| Latest published 1.x release | Yes |
| Older releases | No |

Security fixes are applied to the latest published 1.x release. Users should upgrade to the fixed release as soon as it is available.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/jwtguard/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected version and runtime.
- A minimal reproducing token or script.
- The impact you believe is possible.
- A suggested fix if you have one.

Do not include real signing keys, credentials or customer data in a report.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed release and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

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
