declare module '@aarivbuildz/jwtguard' {
  export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'PS256' | 'ES256' | 'EdDSA';
  export type DangerousHeader = 'jku' | 'x5u' | 'jwk' | 'x5c';

  export type ErrorCode =
    | 'ERR_JWTGUARD_ALGORITHMS_REQUIRED'
    | 'ERR_JWTGUARD_INVALID_ALGORITHM'
    | 'ERR_JWTGUARD_ALG_NONE_FORBIDDEN'
    | 'ERR_JWTGUARD_MALFORMED_TOKEN'
    | 'ERR_JWTGUARD_MALFORMED_JSON'
    | 'ERR_JWTGUARD_INVALID_BASE64URL'
    | 'ERR_JWTGUARD_DUPLICATE_JSON_KEY'
    | 'ERR_JWTGUARD_UNSAFE_KEY'
    | 'ERR_JWTGUARD_DANGEROUS_HEADER'
    | 'ERR_JWTGUARD_INVALID_KID'
    | 'ERR_JWTGUARD_UNKNOWN_CRIT'
    | 'ERR_JWTGUARD_KEY_TYPE_MISMATCH'
    | 'ERR_JWTGUARD_WEAK_SECRET'
    | 'ERR_JWTGUARD_WEAK_KEY'
    | 'ERR_JWTGUARD_INVALID_KEY'
    | 'ERR_JWTGUARD_INVALID_SIGNATURE'
    | 'ERR_JWTGUARD_SIGNATURE_MISMATCH'
    | 'ERR_JWTGUARD_TOKEN_TOO_LARGE'
    | 'ERR_JWTGUARD_EXPIRED'
    | 'ERR_JWTGUARD_NOT_ACTIVE'
    | 'ERR_JWTGUARD_INVALID_IAT'
    | 'ERR_JWTGUARD_INVALID_CLAIM'
    | 'ERR_JWTGUARD_MISSING_CLAIM'
    | 'ERR_JWTGUARD_ISSUER_MISMATCH'
    | 'ERR_JWTGUARD_AUDIENCE_MISMATCH'
    | 'ERR_JWTGUARD_SUBJECT_MISMATCH'
    | 'ERR_JWTGUARD_JTI_MISMATCH'
    | 'ERR_JWTGUARD_INVALID_OPTION';

  export interface JwtGuardError extends Error {
    readonly name: 'JwtGuardError';
    readonly code: ErrorCode;
    readonly details?: unknown;
  }
  export const JwtGuardError: new (code: ErrorCode, message: string, details?: unknown) => JwtGuardError;

  export const ERROR_CODES: Readonly<Record<ErrorCode, ErrorCode>>;
  export const SUPPORTED_ALGORITHMS: readonly Algorithm[];
  export const DANGEROUS_HEADERS: readonly DangerousHeader[];

  export interface JwtHeader {
    alg?: string;
    typ?: string;
    cty?: string;
    kid?: string;
    crit?: string[];
    [key: string]: unknown;
  }

  export interface JwtPayload {
    iss?: string;
    sub?: string;
    aud?: string | string[];
    jti?: string;
    exp?: number;
    nbf?: number;
    iat?: number;
    [key: string]: unknown;
  }

  export interface DecodedJwt {
    readonly header: JwtHeader;
    readonly payload: JwtPayload;
    /** Raw signature bytes (a Buffer, which is a Uint8Array). */
    readonly signature: Uint8Array;
    readonly signingInput: string;
  }

  export type KeyMaterial = string | Uint8Array | object;

  export interface SignOptions {
    /** Required. The algorithm used to sign the token. */
    algorithm: Algorithm;
    /** Registered header claims. alg is always set from `algorithm`. */
    header?: Record<string, unknown>;
    /** Fixed clock or clock provider, in seconds since the epoch. */
    now?: number | (() => number);
    /** Lifetime in seconds. Sets exp. */
    expiresInSeconds?: number;
    /** Delay in seconds before the token is valid. Sets nbf. */
    notBeforeSeconds?: number;
    /** Suppress the automatic iat claim. */
    noTimestamp?: boolean;
    maxTokenBytes?: number;
  }

  export interface VerifyOptions {
    /** Required explicit allowlist. Never inferred from the token header. */
    algorithms: readonly Algorithm[];
    now?: number | (() => number);
    clockToleranceSeconds?: number;
    /** Claim names that must be present. Defaults to ['exp']. */
    requiredClaims?: readonly string[];
    issuer?: string | readonly string[];
    audience?: string | readonly string[];
    subject?: string;
    jwtId?: string;
    /** Requires an iat claim; tokens without iat are rejected. */
    maxAgeSeconds?: number;
    maxTokenBytes?: number;
    /** Headers that are otherwise blocked by default. Use with care. */
    allowDangerousHeaders?: readonly DangerousHeader[];
  }

  export interface DecodeOptions {
    maxTokenBytes?: number;
  }

  export interface InspectOptions extends DecodeOptions {
    /** When true, apply header policy (crit, dangerous headers, kid) to the result. */
    enforcePolicy?: boolean;
    allowDangerousHeaders?: readonly DangerousHeader[];
  }

  export function signJwt(payload: JwtPayload, key: KeyMaterial, options: SignOptions): string;
  export function verifyJwt(token: string, key: KeyMaterial, options: VerifyOptions): JwtPayload;
  export function decodeJwtUnsafe(token: string, options?: DecodeOptions): DecodedJwt;
  export function inspectJwtHeader(token: string, options?: InspectOptions): JwtHeader;
  export function p1363ToDer(signature: Uint8Array): Uint8Array;
  export function derToP1363(signature: Uint8Array): Uint8Array;

  const jwtguard: {
    JwtGuardError: typeof JwtGuardError;
    ERROR_CODES: typeof ERROR_CODES;
    SUPPORTED_ALGORITHMS: typeof SUPPORTED_ALGORITHMS;
    DANGEROUS_HEADERS: typeof DANGEROUS_HEADERS;
    signJwt: typeof signJwt;
    verifyJwt: typeof verifyJwt;
    decodeJwtUnsafe: typeof decodeJwtUnsafe;
    inspectJwtHeader: typeof inspectJwtHeader;
    p1363ToDer: typeof p1363ToDer;
    derToP1363: typeof derToP1363;
  };
  export default jwtguard;
}
