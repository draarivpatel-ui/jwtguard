# Contributing

Thanks for helping improve `jwtguard`.

## Setup

No install step is needed. The package has zero dependencies and uses the Node.js standard library.

```sh
npm test
```

The suite is deterministic: it uses fixed clocks, deterministic secrets and freshly generated ephemeral keypairs for EC signature tests. It runs under both `import()` and `require()`.

## Ground rules for changes

1. Never infer an algorithm from a token. Any new algorithm must be added to `SUPPORTED_ALGORITHMS` and require an explicit allowlist entry.
2. Keep the runtime dependency list empty. Only `node:crypto` and other Node built-ins are allowed.
3. Keep ESM as the single source of truth in `src/index.mjs`. After editing it, run `npm run build:cjs` and commit the regenerated `cjs/index.cjs`.
4. Update `types/index.d.ts` whenever the public API changes.
5. Add regression tests for every security fix, including a negative case that asserts the exact `JwtGuardError.code`.
6. Never introduce em dashes or en dashes into repository text.

## Pull requests

- Keep changes focused and explain the security impact.
- Include tests that fail before your change and pass after it.
- CI runs on Node.js 18, 20 and 22 across Linux, macOS and Windows and checks that the generated CommonJS build is current.

## Commit style

Use short imperative commit subjects. Do not add generated files that are not tracked, and do not commit local configuration or personal paths.
