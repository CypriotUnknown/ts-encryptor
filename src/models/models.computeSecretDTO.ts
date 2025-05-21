import crypto from 'crypto';
import { type Platform } from "./models.platformType";

export interface ComputeSecretDTO {
    platform: Platform;
    clientPublicKeyBase64: string;
    privateKey: crypto.webcrypto.CryptoKey;
} 