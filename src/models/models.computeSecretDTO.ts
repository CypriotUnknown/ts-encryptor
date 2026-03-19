import crypto from 'crypto';
import { type EncryptorPlatform } from "./models.platformType";

/**
 * Parameters for {@linkcode Encryptor.computeSecret}.
 */
export interface ComputeSecretDTO {
    /**
     * The platform that determines how `clientPublicKeyBase64` is decoded.
     *
     * - `"browser"`: the public key string is a JSON-stringified JWK.
     * - `"app"`: the public key string is a Base64-encoded SPKI DER binary.
     */
    platform: EncryptorPlatform;

    /**
     * The other party's serialized public key.
     *
     * The format must match the chosen {@linkcode platform}:
     * JWK JSON string for `"browser"`, Base64 SPKI for `"app"`.
     */
    clientPublicKeyBase64: string;

    /**
     * Your own ECDH private key, typically obtained from the `privateKey`
     * field of {@linkcode Encryptor.generateKeys} or re-imported via
     * {@linkcode Encryptor.generateCryptoKeyFromBase64}.
     */
    privateKey: crypto.webcrypto.CryptoKey;
}