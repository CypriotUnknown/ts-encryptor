import crypto from 'node:crypto';
import { type EncryptedBodyDTO } from './models/models.encryptedRequestBodyDTO';
import { StringUtility } from './utils/string';
import { type SecurityKeysOutput } from './models/models.securityKeysOutput';
import { type ComputeSecretDTO } from "./models/models.computeSecretDTO";
import { EncryptorPlatform } from './models/models.platformType';

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

    public static get instance(): Encryptor {
        if (this.sharedInstance === undefined) this.sharedInstance = new Encryptor();
        return this.sharedInstance;
    }

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