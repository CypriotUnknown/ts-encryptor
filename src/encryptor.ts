import crypto from 'node:crypto';
import { type EncryptedBodyDTO } from './models/models.encryptedRequestBodyDTO';
import { StringUtility } from './utils/string';
import { type SecurityKeysOutput } from './models/models.securityKeysOutput';
import { type ComputePostmanSecretDTO } from "./models/models.computePostmanSecretDTO";
import { type ComputeSecretDTO } from "./models/models.computeSecretDTO";

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

    public static async generateJWKKeys() {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

        const publicKeyString = JSON.stringify(publicKeyJwk);
        const privateKeyString = JSON.stringify(privateKeyJwk);

        return {
            privateKeyString,
            publicKeyString,
            privateKey: keyPair.privateKey
        };
    }

    public static async generateKeys(): Promise<SecurityKeysOutput> {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyString = StringUtility.arrayBufferToString({ buffer: publicKeyBuffer, encoding: this.keyEncoding });

        const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const privateKeyString = StringUtility.arrayBufferToString({ buffer: privateKeyBuffer, encoding: this.keyEncoding });

        return {
            privateKeyString,
            publicKeyString,
            privateKey: keyPair.privateKey
        };
    }

    private static async generateJWKCryptoKeyFromBase64String(base64KeyString: string, forPostman: boolean = false): Promise<CryptoKey> {
        const keyJwk = JSON.parse(base64KeyString);
        return await crypto.subtle.importKey(
            "jwk",
            keyJwk,
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            forPostman ? ['deriveBits', 'deriveKey'] : []
        );
    }

    private static async generateCryptoKeyFromBase64String(base64KeyString: string, forPostman: boolean = false): Promise<CryptoKey> {
        return await crypto.subtle.importKey(
            forPostman ? "pkcs8" : "spki",
            StringUtility.stringToArrayBuffer({ string: base64KeyString, encoding: this.keyEncoding }),
            {
                name: this.keyAlgorithm,
                namedCurve: this.curve,
            },
            true,
            forPostman ? ['deriveBits', 'deriveKey'] : []
        );
    }

    // FOR DEV PURPOSES
    public static async computePostmanSecret(dto: ComputePostmanSecretDTO): Promise<string> {
        const { postmanPrivateKeyBase64, serverPublicKeyBase64 } = dto;
        const postmanPrivateKey = await this.generateCryptoKeyFromBase64String(postmanPrivateKeyBase64, true);
        const serverPublicKey = await this.generateCryptoKeyFromBase64String(serverPublicKeyBase64);

        const sharedSecret = await this.deriveBits({ privateKey: postmanPrivateKey, publicKey: serverPublicKey });
        const digestBuffer = await crypto.subtle.digest({ name: "SHA-256" }, sharedSecret);
        return StringUtility.arrayBufferToString({ buffer: digestBuffer, encoding: this.secretEncoding });
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
        const { clientPublicKeyBase64, privateKey, jwk } = dto;
        let publicKey: CryptoKey;

        if (jwk) {
            publicKey = await this.generateJWKCryptoKeyFromBase64String(clientPublicKeyBase64);
        } else {
            publicKey = await this.generateCryptoKeyFromBase64String(clientPublicKeyBase64);
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

    public static async encryptContent(dto: { content: string; secret: string; }): Promise<EncryptedBodyDTO> {
        const { content, secret } = dto;
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
            hash: encrypted.toString(this.clientEncoding)
        };
    }

    public static async decryptContent(dto: { content: EncryptedBodyDTO, secret: string }): Promise<string> {
        const { content, secret } = dto;
        const decipher = crypto.createDecipheriv(
            this.encrpytionAlgorithm,
            Buffer.from(secret, this.secretEncoding),
            Buffer.from(content.iv, this.ivEncoding)
        );

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(content.hash, this.clientEncoding)),
            decipher.final()
        ]);

        return decrypted.toString();
    }
}