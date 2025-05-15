import crypto from 'crypto';

export interface ComputeSecretDTO {
    jwk: boolean;
    clientPublicKeyBase64: string;
    privateKey: crypto.webcrypto.CryptoKey;
} 