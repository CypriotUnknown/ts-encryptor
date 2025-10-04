# 🔐 Encryptor

A TypeScript utility for performing secure ECDH key exchange, AES encryption/decryption, and shared-secret computation between a **browser** and an **app** platform.

---

## 🚀 Features

- Generate ECDH key pairs (`P-256` curve)
- Import/export keys for both **browser (JWK)** and **app (SPKI/PKCS8)** platforms
- Compute shared secrets via `ECDH`
- AES-256-CBC symmetric encryption and decryption
- Utility methods for random digits (e.g. OTP)
- Works seamlessly in **Node.js 18+** (uses `crypto.subtle`)

---

## Usage

### 1. Generate keys

```ts
import Encryptor from '@cypriot/encryptor';

// Browser platform (uses JWK)
const browserKeys = await Encryptor.generateKeys({ platform: "browser" });

// App platform (uses PKCS8/SPKI)
const appKeys = await Encryptor.generateKeys({ platform: "app" });
```

This function returns:
```ts
/*
{
  privateKeyString: string;
  publicKeyString: string;
  privateKey: CryptoKey;
}
*/
```

### 2. Import Keys from Base64

```ts
// For browser
const browserKey = await Encryptor.generateCryptoKeyFromBase64({
  platform: "browser",
  base64KeyString: browserKeys.publicKeyString
});

// For app
const appPrivateKey = await Encryptor.generateCryptoKeyFromBase64({
  platform: "app",
  base64KeyString: appKeys.privateKeyString,
  returnKey: "private"
});
```

### 3. Compute a Shared Secret

```ts
const sharedSecret = await Encryptor.computeSecret({
  clientPublicKeyBase64: browserKeys.publicKeyString,
  privateKey: appPrivateKey,
  platform: "app"
});
```

This produces a base64-encoded shared secret.

### 4. Encrypt/Decrypt Data

```ts
const encrypted = await Encryptor.encryptContent({
  content: JSON.stringify({ message: "Hello World" }),
  secret: sharedSecret,
  platform: "app"
});

const decrypted = await Encryptor.decryptContent({
  content: encrypted,
  secret: sharedSecret,
  platform: "app"
});

console.log(decrypted); // {"message":"Hello World"}
```

## 🧩 Supported Platforms

The `Encryptor` class supports two platforms, each with different key formats and usage:

| Platform | Key Format | Description | Example Use Case |
|-----------|-------------|--------------|------------------|
| **browser** | JWK (JSON Web Key) | Uses JSON-based keys for compatibility with Web Crypto API. Keys are exported/imported as JSON strings. | Web clients running in the browser. |
| **app** | SPKI / PKCS8 | Uses Base64-encoded DER keys for stronger control and compactness. Keys are exported/imported as binary data encoded in Base64. | Mobile or desktop apps, or Node.js backends. |


## Example Usage

Suppose two different applications want to share an encrypted message with each other. The following procedure could be used:

### Step 1:

Application 1 and 2 each generate their key pairs using the `generateKeys` function. Private keys should NEVER leave the application and should be kept securely.

### Step 2:

The applications share their `publicKeyString` with each other.

### Step 3:

With the `publicKeyString` of each other, the applications can each compute the shared secret. This secret should NEVER leave the application scope and should be kept securely.

### Step 4:

The message to send gets encrypted using the `encryptContent` function. The returning object is then sent to the other application.

### Step 5:

The receiving application decrypts the message using the `decryptContent` function. This returns the message as a string.

### Example code:

```ts
const platform: EncryptorPlatform = "app";

const clientKeys = await Encryptor.generateKeys({ platform });
const serverKeys = await Encryptor.generateKeys({ platform });

const message = {
    hello: "world"
};

const sharedSecret = await Encryptor.computeSecret({
    clientPublicKeyBase64: clientKeys.publicKeyString,
    platform,
    privateKey: serverKeys.privateKey
});

const encrypted = await Encryptor.encryptContent({ content: JSON.stringify(message), platform, secret: sharedSecret });

console.log({ encrypted });

const decrypted = await Encryptor.decryptContent({
    content: encrypted,
    secret: sharedSecret,
    platform
}).then(d => JSON.parse(d));


console.log({ decrypted });
```

Output:
```
{
  encrypted: {
    iv: "bBJXZLp5XIKF68Xcdu3Ecg==",
    hash: "FYrQAVSeDhkG40dpYDeP5WH1P7U68qV+eayPH4mxcU4=",
  },
}
{
  decrypted: {
    hello: "world",
  },
}
```