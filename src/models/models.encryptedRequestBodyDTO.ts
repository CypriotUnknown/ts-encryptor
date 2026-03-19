/**
 * The output of {@linkcode Encryptor.encryptContent} and the expected input of
 * {@linkcode Encryptor.decryptContent}.
 *
 * Contains the AES-256-CBC initialization vector and the encrypted ciphertext.
 * Both fields must be transmitted together for decryption to succeed.
 */
export interface EncryptedBodyDTO {
    /**
     * The Base64-encoded AES initialization vector (16 random bytes).
     *
     * Must be passed unchanged to {@linkcode Encryptor.decryptContent}.
     */
    iv: string;

    /**
     * The encrypted ciphertext.
     *
     * - For `"app"` platform: Base64-encoded.
     * - For `"browser"` platform: hex-encoded.
     */
    hash: string;
}