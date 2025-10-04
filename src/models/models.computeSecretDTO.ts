import crypto from 'crypto';
import { type EncryptorPlatform } from "./models.platformType";

export interface ComputeSecretDTO {
    platform: EncryptorPlatform;
    clientPublicKeyBase64: string;
    privateKey: crypto.webcrypto.CryptoKey;
} 