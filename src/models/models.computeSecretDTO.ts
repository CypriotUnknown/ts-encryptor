import crypto from 'crypto';

export default interface ComputeSecretDTO {
    clientPublicKeyBase64: string;
    privateKey: crypto.webcrypto.CryptoKey;
} 