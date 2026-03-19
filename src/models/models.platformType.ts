/**
 * The platform context for key serialization and cipher output encoding.
 *
 * - `"app"` — uses SPKI/PKCS8 (Base64 DER) keys and Base64-encoded cipher output.
 *   Suitable for mobile apps, desktop clients, and Node.js/Bun backends.
 * - `"browser"` — uses JWK keys and hex-encoded cipher output.
 *   Suitable for web clients using the Web Crypto API.
 */
export type EncryptorPlatform = "app" | "browser";