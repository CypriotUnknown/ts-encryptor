import crypto from "crypto";

/**
 * The result of {@linkcode Encryptor.generateKeys}.
 *
 * Contains both the serialized (string) and native (`CryptoKey`) representations
 * of the generated ECDH key pair.
 */
export interface SecurityKeysOutput {
    /**
     * The serialized private key.
     *
     * - For `"browser"` platform: a JSON-stringified JWK object.
     * - For `"app"` platform: a Base64-encoded PKCS8 DER binary.
     *
     * **Keep this value secret and never share it.**
     */
    privateKeyString: string;

    /**
     * The serialized public key.
     *
     * - For `"browser"` platform: a JSON-stringified JWK object.
     * - For `"app"` platform: a Base64-encoded SPKI DER binary.
     *
     * This value is safe to share with the other party for ECDH key exchange.
     */
    publicKeyString: string;

    /**
     * The native `CryptoKey` private key, ready to be passed directly to
     * {@linkcode Encryptor.computeSecret} without re-importing.
     */
    privateKey: crypto.webcrypto.CryptoKey;
}