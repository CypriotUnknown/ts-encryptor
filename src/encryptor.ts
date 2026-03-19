import crypto from 'node:crypto';
import { type EncryptedBodyDTO } from './models/models.encryptedRequestBodyDTO';
import { StringUtility } from './utils/string';
import { type SecurityKeysOutput } from './models/models.securityKeysOutput';
import { type ComputeSecretDTO } from "./models/models.computeSecretDTO";
import { EncryptorPlatform } from './models/models.platformType';

/**
 * A static utility class for ECDH key exchange, AES-256-CBC encryption/decryption,
 * and shared-secret computation.
 *
 * Supports two platform modes:
 * - `"browser"` — JWK-based keys, hex cipher output. For Web Crypto API clients.
 * - `"app"` — SPKI/PKCS8 keys, Base64 cipher output. For Node.js, Bun, and mobile apps.
 *
 * All cryptographic operations use the native `crypto.subtle` Web Crypto API
 * (available in Node.js 18+, Bun, and modern browsers).
 *
 * @example
 * ```ts
 * import Encryptor from "@cypriot/encryptor";
 *
 * const platform = "app";
 * const clientKeys = await Encryptor.generateKeys({ platform });
 * const serverKeys = await Encryptor.generateKeys({ platform });
 *
 * const secret = await Encryptor.computeSecret({
 *   clientPublicKeyBase64: clientKeys.publicKeyString,
 *   privateKey: serverKeys.privateKey,
 *   platform,
 * });
 *
 * const encrypted = await Encryptor.encryptContent({
 *   content: JSON.stringify({ hello: "world" }),
 *   secret,
 *   platform,
 * });
 *
 * const decrypted = await Encryptor.decryptContent({ content: encrypted, secret, platform });
 * console.log(decrypted); // {"hello":"world"}
 * ```
 */
export class Encryptor {
    private static sharedInstance: Encryptor | undefined;
    private static readonly curve = "P-256";
    private static readonly keyAlgorithm = "ECDH";
    private static readonly encrpytionAlgorithm = 'aes-256-cbc';

    private static readonly clientEncoding: BufferEncoding = "hex";
    private static readonly secretEncoding: BufferEncoding = "base64";
    private static readonly ivEncoding: BufferEncoding = "base64";
    private static readonly keyEncoding: BufferEncoding = "base64";

    private constructor() { }

    /**
     * Returns the singleton instance of `Encryptor`.
     *
     * Note: all methods on this class are static, so the instance is rarely
     * needed directly. It is provided for compatibility with dependency-injection
     * patterns that require an object reference.
     */
    public static get instance(): Encryptor {
        if (this.sharedInstance === undefined) this.sharedInstance = new Encryptor();
        return this.sharedInstance;
    }

    /**
     * Generates a new ECDH P-256 key pair and returns both the serialized strings
     * and the native `CryptoKey` private key.
     *
     * @param params.platform - The target platform, which determines the key serialization format.
     * @returns The generated key pair as a {@linkcode SecurityKeysOutput}.
     *
     * @example
     * ```ts
     * const keys = await Encryptor.generateKeys({ platform: "app" });
     * console.log(keys.publicKeyString); // Base64 SPKI
     * console.log(keys.privateKeyString); // Base64 PKCS8
     * ```
     */
    public static async generateKeys(params: { platform: "browser" | "app" }): Promise<SecurityKeysOutput> {
        const { platform } = params;
        const keyPair = await crypto.subtle.generateKey(
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        const keyFormat = platform === "browser" ? "jwk" : "spki";

        let publicKeyString: string;
        let privateKeyString: string;

        if (keyFormat === "jwk") {
            const publicKeyJwk = await crypto.subtle.exportKey(keyFormat, keyPair.publicKey);
            const privateKeyJwk = await crypto.subtle.exportKey(keyFormat, keyPair.privateKey);

            publicKeyString = JSON.stringify(publicKeyJwk);
            privateKeyString = JSON.stringify(privateKeyJwk);
        } else {
            const publicKeyBuffer = await crypto.subtle.exportKey(keyFormat, keyPair.publicKey);
            const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

            publicKeyString = StringUtility.arrayBufferToString({ buffer: publicKeyBuffer, encoding: this.keyEncoding });
            privateKeyString = StringUtility.arrayBufferToString({ buffer: privateKeyBuffer, encoding: this.keyEncoding });
        }

        return {
            privateKeyString,
            publicKeyString,
            privateKey: keyPair.privateKey
        };
    }

    private static async generateJWKCryptoKeyFromBase64String(base64KeyString: string): Promise<CryptoKey> {
        const keyJwk = JSON.parse(base64KeyString);

        const isPrivateKey = !!keyJwk.d;
        const usages = isPrivateKey
            ? (["deriveBits", "deriveKey"] as const)
            : ([] as const);

        return await crypto.subtle.importKey(
            "jwk",
            keyJwk,
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            usages
        );
    }

    private static async generateCryptoKeyFromBase64StringForAppPlatform(base64KeyString: string, returnKey: "private" | "public"): Promise<CryptoKey> {
        const keyFormat = returnKey === "private" ? "pkcs8" : "spki";
        const usages: KeyUsage[] =
            returnKey === "private"
                ? ["deriveBits", "deriveKey"]
                : [];

        return await crypto.subtle.importKey(
            keyFormat,
            StringUtility.stringToArrayBuffer({ string: base64KeyString, encoding: this.keyEncoding }),
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            usages
        );
    }

    /**
     * Imports a serialized key string back into a native `CryptoKey`.
     *
     * Use this when you need to reconstruct a key from a stored or transmitted
     * string (e.g., a private key loaded from secure storage, or a peer's public key).
     *
     * @param params.platform - The platform that defines the key format.
     * @param params.base64KeyString - The serialized key string to import.
     * @param params.returnKey - (`"app"` platform only) Whether to import the key as
     *   `"private"` (PKCS8) or `"public"` (SPKI).
     * @returns The imported `CryptoKey`.
     *
     * @example
     * ```ts
     * // Re-import a stored app private key
     * const privateKey = await Encryptor.generateCryptoKeyFromBase64({
     *   platform: "app",
     *   base64KeyString: storedPrivateKeyString,
     *   returnKey: "private",
     * });
     *
     * // Import a peer's browser public key
     * const publicKey = await Encryptor.generateCryptoKeyFromBase64({
     *   platform: "browser",
     *   base64KeyString: peerPublicKeyJson,
     * });
     * ```
     */
    public static async generateCryptoKeyFromBase64(
        params:
            | { platform: "browser"; base64KeyString: string; }
            | { platform: "app"; base64KeyString: string; returnKey: "private" | "public" }
    ): Promise<CryptoKey> {
        const { base64KeyString, platform } = params;
        if (platform === "app") {
            return this.generateCryptoKeyFromBase64StringForAppPlatform(base64KeyString, params.returnKey);
        } else {
            return this.generateJWKCryptoKeyFromBase64String(base64KeyString);
        }
    }

    private static async deriveBits(params: { publicKey: crypto.webcrypto.CryptoKey; privateKey: crypto.webcrypto.CryptoKey; }): Promise<ArrayBuffer> {
        const { publicKey, privateKey } = params;
        return await crypto.subtle.deriveBits(
            {
                name: this.keyAlgorithm,
                public: publicKey,
            },
            privateKey,
            256 // length
        );
    }

    /**
     * Derives a shared secret from your private key and the other party's public key
     * using ECDH, then hashes it with SHA-256.
     *
     * Both parties independently calling this method with each other's public keys
     * will arrive at the same secret — without ever transmitting it.
     *
     * @param dto - See {@linkcode ComputeSecretDTO}.
     * @returns A Base64-encoded, SHA-256-hashed shared secret string suitable for use
     *   as an AES-256 key in {@linkcode encryptContent} / {@linkcode decryptContent}.
     *
     * @example
     * ```ts
     * const secret = await Encryptor.computeSecret({
     *   clientPublicKeyBase64: peerPublicKeyString,
     *   privateKey: myKeys.privateKey,
     *   platform: "app",
     * });
     * ```
     */
    public static async computeSecret(dto: ComputeSecretDTO): Promise<string> {
        const { clientPublicKeyBase64, privateKey, platform } = dto;
        let publicKey: CryptoKey;

        if (platform === "browser") {
            publicKey = await this.generateJWKCryptoKeyFromBase64String(clientPublicKeyBase64);
        } else {
            publicKey = await this.generateCryptoKeyFromBase64StringForAppPlatform(clientPublicKeyBase64, "public");
        }

        const sharedSecret = await this.deriveBits({ privateKey, publicKey });

        const digestBuffer = await crypto.subtle.digest({ name: "SHA-256" }, sharedSecret);
        return StringUtility.arrayBufferToString({ buffer: digestBuffer, encoding: this.secretEncoding });
    }

    /**
     * Generates a string of random decimal digits (0–9).
     *
     * Useful for generating OTP codes or other numeric tokens.
     *
     * @param dto.maxDigits - The number of digits to generate. Defaults to `6`.
     * @returns A string of random digits of the requested length.
     *
     * @example
     * ```ts
     * const otp = Encryptor.generateRandomDigits({ maxDigits: 6 });
     * console.log(otp); // e.g. "482031"
     * ```
     */
    public static generateRandomDigits(dto?: { maxDigits: number }): string {
        const maxDigits = dto?.maxDigits ?? 6;

        let possibleDigits: string[] = [];
        let OTP = '';

        for (let digitIndex = 0; digitIndex < maxDigits; digitIndex++) {
            possibleDigits.push(digitIndex.toString());
        }

        for (let i = 0; i < maxDigits; i++) {
            OTP += possibleDigits[Math.floor(Math.random() * maxDigits)];
        }

        return OTP;
    }

    /**
     * Encrypts a string using AES-256-CBC with a random initialization vector.
     *
     * The `secret` must be a Base64-encoded 256-bit key — typically the output of
     * {@linkcode computeSecret}.
     *
     * @param dto.content - The plaintext string to encrypt.
     * @param dto.secret - The Base64-encoded shared secret (32-byte AES key).
     * @param dto.platform - Determines the ciphertext encoding:
     *   `"app"` produces Base64, `"browser"` produces hex.
     * @returns An {@linkcode EncryptedBodyDTO} containing the IV and ciphertext.
     *
     * @example
     * ```ts
     * const encrypted = await Encryptor.encryptContent({
     *   content: JSON.stringify({ hello: "world" }),
     *   secret: sharedSecret,
     *   platform: "app",
     * });
     * // { iv: "...", hash: "..." }
     * ```
     */
    public static async encryptContent(dto: { content: string; secret: string; platform: EncryptorPlatform; }): Promise<EncryptedBodyDTO> {
        const { content, secret, platform } = dto;
        const iv = crypto.randomBytes(16).toString(this.ivEncoding);

        const cipher = crypto.createCipheriv(
            this.encrpytionAlgorithm,
            Buffer.from(secret, this.secretEncoding),
            Buffer.from(iv, this.ivEncoding)
        );

        const encrypted = Buffer.concat([
            cipher.update(content),
            cipher.final()
        ]);

        return {
            iv,
            hash: encrypted.toString(platform === "app" ? "base64" : this.clientEncoding)
        };
    }

    /**
     * Decrypts an {@linkcode EncryptedBodyDTO} produced by {@linkcode encryptContent}.
     *
     * The `secret` and `platform` must match the values used during encryption.
     *
     * @param dto.content - The {@linkcode EncryptedBodyDTO} to decrypt.
     * @param dto.secret - The Base64-encoded shared secret (32-byte AES key).
     * @param dto.platform - Must match the platform used during encryption.
     * @returns The decrypted plaintext string.
     *
     * @example
     * ```ts
     * const decrypted = await Encryptor.decryptContent({
     *   content: encrypted,
     *   secret: sharedSecret,
     *   platform: "app",
     * });
     * console.log(decrypted); // '{"hello":"world"}'
     * ```
     */
    public static async decryptContent(dto: { content: EncryptedBodyDTO, secret: string; platform: EncryptorPlatform; }): Promise<string> {
        const { content, secret, platform } = dto;
        const decipher = crypto.createDecipheriv(
            this.encrpytionAlgorithm,
            Buffer.from(secret, this.secretEncoding),
            Buffer.from(content.iv, this.ivEncoding)
        );

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(content.hash, platform === "app" ? "base64" : this.clientEncoding)),
            decipher.final()
        ]);

        return decrypted.toString();
    }
}