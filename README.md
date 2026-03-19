# Encryptor

A TypeScript utility for ECDH key exchange, AES-256-CBC encryption/decryption, and shared-secret computation between a **browser** and an **app** platform.

---

## Installation

**JSR (Deno / Bun / Node.js)**
```sh
deno add jsr:@cypriot/encryptor
bunx jsr add @cypriot/encryptor
npx jsr add @cypriot/encryptor
```

**npm**
```sh
npm install @cypriotunknown/encryptor
```

---

## Features

- Generate ECDH key pairs (`P-256` curve)
- Import/export keys for both **browser (JWK)** and **app (SPKI/PKCS8)** platforms
- Compute shared secrets via ECDH + SHA-256
- AES-256-CBC symmetric encryption and decryption
- Random digit generation (e.g. OTP codes)
- Works in **Node.js 18+**, **Bun**, and modern **browsers** (uses `crypto.subtle`)

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

Returns a `SecurityKeysOutput`:
```ts
{
  privateKeyString: string; // serialized private key — never share this
  publicKeyString: string;  // serialized public key — share with the other party
  privateKey: CryptoKey;    // native CryptoKey, ready to use directly
}
```

### 2. Import a key from a string

```ts
// Re-import a stored app private key
const privateKey = await Encryptor.generateCryptoKeyFromBase64({
  platform: "app",
  base64KeyString: appKeys.privateKeyString,
  returnKey: "private",
});

// Import a peer's browser public key
const publicKey = await Encryptor.generateCryptoKeyFromBase64({
  platform: "browser",
  base64KeyString: browserKeys.publicKeyString,
});
```

### 3. Compute a shared secret

```ts
const sharedSecret = await Encryptor.computeSecret({
  clientPublicKeyBase64: browserKeys.publicKeyString,
  privateKey: appPrivateKey,
  platform: "app",
});
```

Returns a Base64-encoded, SHA-256-hashed shared secret.

### 4. Generate random digits (OTP)

```ts
const otp = Encryptor.generateRandomDigits({ maxDigits: 6 });
console.log(otp); // e.g. "482031"
```

### 5. Encrypt and decrypt

```ts
const encrypted = await Encryptor.encryptContent({
  content: JSON.stringify({ message: "Hello World" }),
  secret: sharedSecret,
  platform: "app",
});

const decrypted = await Encryptor.decryptContent({
  content: encrypted,
  secret: sharedSecret,
  platform: "app",
});

console.log(decrypted); // {"message":"Hello World"}
```

---

## Supported Platforms

| Platform | Key Format | Cipher Output | Typical Use Case |
|----------|------------|---------------|------------------|
| `"browser"` | JWK (JSON string) | Hex | Web clients using the Web Crypto API |
| `"app"` | SPKI / PKCS8 (Base64) | Base64 | Mobile/desktop apps, Node.js/Bun backends |

---

## Full Example

Two applications exchanging an encrypted message:

```ts
import Encryptor, { type EncryptorPlatform } from '@cypriot/encryptor';

const platform: EncryptorPlatform = "app";

const clientKeys = await Encryptor.generateKeys({ platform });
const serverKeys = await Encryptor.generateKeys({ platform });

// Each party computes the same shared secret from the other's public key
const sharedSecret = await Encryptor.computeSecret({
  clientPublicKeyBase64: clientKeys.publicKeyString,
  privateKey: serverKeys.privateKey,
  platform,
});

const encrypted = await Encryptor.encryptContent({
  content: JSON.stringify({ hello: "world" }),
  platform,
  secret: sharedSecret,
});

console.log(encrypted);
// { iv: "bBJXZLp5XIKF68Xcdu3Ecg==", hash: "FYrQAVSeDhk..." }

const decrypted = await Encryptor.decryptContent({
  content: encrypted,
  secret: sharedSecret,
  platform,
}).then(d => JSON.parse(d));

console.log(decrypted);
// { hello: "world" }
```

---

## Related Packages

| Language | Package |
|----------|---------|
| Swift    | [`SwiftEncryptor`](https://github.com/CypriotUnknown/swift-encryptor) — iOS 15+ / macOS 12+ / tvOS 15+ / watchOS 8+, built on CryptoKit and CommonCrypto |
| Go       | [`encryptor-go`](https://github.com/CypriotUnknown/encryptor-go) — `go get github.com/CypriotUnknown/encryptor-go` |

All three implementations share the same P-256 curve, SHA-256 secret digest, AES-256-CBC cipher, and `"app"`/`"browser"` platform conventions, so any pair can interoperate directly.

---

## License

MIT
