/**
 * @module
 *
 * `@cypriot/encryptor` — ECDH key exchange and AES-256-CBC encryption for Node.js, Bun, and browsers.
 *
 * Provides the {@linkcode Encryptor} class and its supporting types for performing
 * end-to-end encrypted communication between two parties using P-256 ECDH and AES-256-CBC.
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
import { Encryptor } from "./src/encryptor";
import { type ComputeSecretDTO } from "./src/models/models.computeSecretDTO";
import { type EncryptedBodyDTO } from "./src/models/models.encryptedRequestBodyDTO";
import { type SecurityKeysOutput } from "./src/models/models.securityKeysOutput";
import { type EncryptorPlatform } from "./src/models/models.platformType";

export default Encryptor;

export {
    type ComputeSecretDTO,
    type EncryptedBodyDTO,
    type SecurityKeysOutput,
    type EncryptorPlatform
}