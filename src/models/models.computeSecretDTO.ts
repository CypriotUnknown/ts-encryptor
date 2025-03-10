import crypto from 'crypto';

export interface ComputeSecretDTO {
    clientPublicKeyBase64: string;
    privateKey: crypto.webcrypto.CryptoKey;
} 