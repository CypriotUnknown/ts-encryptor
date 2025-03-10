import crypto from "crypto";

export default interface SecurityKeysOutput {
    privateKeyString: string;
    publicKeyString: string;
    privateKey: crypto.webcrypto.CryptoKey;
}