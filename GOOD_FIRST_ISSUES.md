# Good first issues

These are concrete, bounded contributions. Each one should keep the runtime dependency list empty and include tests under `tests/`.

1. **JWKS resolver module.** Add `src/jwks.mjs` with `createJwksResolver({ fetchJson, allowedIssuers })` that fetches a fixed, allowlisted JWKS URL and returns a key for a validated `kid`. Never fetch a URL supplied inside a token.
2. **JWKS caching.** Add a TTL and an in-flight request deduplication cache to the JWKS resolver. Test expiry, refresh failure and concurrent requests.
3. **`RS384` support.** Use SHA-384 for RSA PKCS#1 v1.5, add it to `SUPPORTED_ALGORITHMS`, an HMAC-style minimum-key rule is not applicable, and add full roundtrip and confusion tests.
4. **`RS512` support.** Use SHA-512 for RSA PKCS#1 v1.5 with roundtrip, wrong-key and tampered-signature tests.
5. **`PS384` support.** Use SHA-384 with a 48 byte PSS salt length. Assert that a PS384 token fails verification under PS256.
6. **`PS512` support.** Use SHA-512 with a 64 byte PSS salt length and matching tests.
7. **`ES384` support.** Use the P-384 curve, generate 96 byte raw signatures and extend the P1363/DER conversion helpers to a 48 byte component width.
8. **`ES512` support.** Use the P-521 curve, 132 byte raw signatures and a 66 byte component width. Verify the DER converter handles the high bit correctly.
9. **`Ed448` support.** Add Ed448 under a distinct algorithm name, with dedicated keypair tests and key-type checks.
10. **Express middleware adapter.** Add `src/adapters/express.mjs` exporting `jwtGuardMiddleware({ algorithms, key, ...verifyOptions })` that reads only the `Authorization: Bearer` header, calls `verifyJwt` and stores claims on the request.
11. **Fetch middleware adapter.** Add a `withJwtGuard(handler, options)` wrapper for Web `Request` objects that rejects malformed authorization headers before invoking the handler.
12. **Fastify plugin.** Add a plugin that registers a `preHandler` hook using `verifyJwt` and exposes verified claims through the request object.
13. **`decodeJwtComplete` helper.** Return decoded header, payload and a verification result object instead of throwing, with an explicit `ok` discriminator. Keep `verifyJwt` as the strict default.
14. **Token size and claim size profiling.** Add a benchmark script under `scripts/` that measures signing and verification for each algorithm at 1 KB, 16 KB and 64 KB payloads, with no new dependencies.
15. **Type-level test file.** Add a compile-checked `tests/types.test.ts` that asserts wrong algorithms, missing `algorithms` and unknown error codes fail type checking where a TypeScript devDependency is available. Keep it out of the zero-dependency runtime path.

If you pick one of these, open an issue first so work is not duplicated.
