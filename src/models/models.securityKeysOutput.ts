import crypto from "crypto";

export interface SecurityKeysOutput {
    privateKeyString: string;
    publicKeyString: string;
    privateKey: crypto.webcrypto.CryptoKey;
}