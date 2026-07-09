# CipherKit

On-device cryptography toolkit built on Apple **CryptoKit** + **Security** — no third-party dependencies. Split into products so you import only what you need.

| Product | Import for | Extra system frameworks |
|---|---|---|
| **CipherKit** | Core crypto: encryption, hashing, KDF, signing, 2FA, JWT verify, Keychain, passcode | CryptoKit, Security |
| **CipherFile** | Chunked large-file encryption, key rotation, streaming file hash | + FileHandle |
| **CipherBiometric** | Face ID / Touch ID gated Secure Enclave keys & vault | + LocalAuthentication |
| **CipherServer** | JWT **signing**, RSA private-key (decrypt/sign), TLS public-key pinning | + URLSession |

```swift
// Package.swift
.product(name: "AnvyxCipherKit", package: "CipherKit")          // always
.product(name: "AnvyxCipherFile", package: "CipherKit")         // if you need file encryption
.product(name: "AnvyxCipherBiometric", package: "CipherKit")    // if you need Face ID keys
.product(name: "AnvyxCipherServer", package: "CipherKit")       // if you talk to a server
```

Requires **iOS 16+**. Secure Enclave / biometrics / Keychain need a **real device** (not the Simulator).

---

## CipherKit (core)

### Symmetric encryption (AES-GCM / ChaCha20-Poly1305)
```swift
let key = AESGCM.randomKey()
let sealed = try AESGCM.seal(Data("secret".utf8), using: key)     // combined nonce+ct+tag
let plain  = try AESGCM.open(sealed, using: key)

// with Additional Authenticated Data (header bound to ciphertext)
let s = try AESGCM.seal(body, using: key, authenticating: Data("v1".utf8))

// Codable at rest
let blob = try SecretBox.encrypt(myModel, using: key)
let model: MyModel = try SecretBox.decrypt(MyModel.self, from: blob, using: key)
```

### Envelope encryption (rotate the master cheaply)
```swift
let sealed = try Envelope.seal(bigData, master: masterKey)         // wraps a random data key
let data   = try Envelope.open(sealed, master: masterKey)
let rotated = try Envelope.rewrap(sealed, from: oldMaster, to: newMaster)  // ciphertext untouched
```

### Hashing / KDF / random
```swift
Hashing.sha256Hex(data)
Hashing.hmacSHA256(data, key: k)
let key = KeyDerivation.pbkdf2(password: "pw", salt: salt)          // password → key
let sub = KeyDerivation.hkdf(from: key, info: Data("ctx".utf8))
let pw  = PasswordGenerator.generate(.init(length: 20))
let rnd = CryptoRandom.bytes(32)
```

### Signing & key agreement
```swift
let k = Ed25519.generateKey()
let sig = try Ed25519.sign(data, with: k)
Ed25519.verify(sig, of: data, with: k.publicKey)

let shared = try KeyAgreement.sharedKey(privateKey: mine, peerPublicKey: theirs)   // ECDH → SymmetricKey
```

### 2FA (TOTP / HOTP)
```swift
let uri = OTPAuthURI("otpauth://totp/Anvyx:me?secret=JBSWY3DPEHPK3PXP&issuer=Anvyx")!
uri.currentCode()                         // 6-digit code now
TOTP.secondsRemaining()                   // countdown
```

### JWT (verify) — offline Sign in with Apple
```swift
guard let jwt = JWT(identityToken) else { return }
JWTVerifier.verifyRS256(jwt, publicKeyDER: applePublicKeyDER)      // ES256 / HS256 also supported
JWTVerifier.validateClaims(jwt, issuer: "https://appleid.apple.com",
                           audience: "com.you.app", nonce: nonce)
```

### Local passcode + Keychain
```swift
let hashed = Passcode.hash("1234")                                 // store `hashed`, never the PIN
Passcode.verify("1234", against: hashed)

var state = PasscodeThrottle.recordFailure(state)                  // brute-force lockout
PasscodeThrottle.isLockedOut(state)

let store = KeychainStore(service: "com.you.app")
try store.setKey(key, for: "vault")
let key = store.key(for: "vault")

var secret = Data(...); secret.secureZero()                        // wipe from memory
```

---

## CipherFile
```swift
try EncryptedFileStore.encrypt(fileAt: src, to: dst, using: key)   // streamed, chunked
try EncryptedFileStore.decrypt(fileAt: dst, to: out, using: key)
try KeyRotation.reencryptFile(at: dst, from: oldKey, to: newKey)
let digest = try FileHash.sha256(fileAt: url)                      // hash big files
```

## CipherBiometric (device only)
```swift
let key = try BiometricKey.generate()                              // Secure Enclave, Face ID gated
let sig = try BiometricKey.sign(data, with: key)                   // prompts Face ID
// or a full vault:
let sealed = try BiometricVault.encrypt(data, account: "notes", reason: "Unlock notes")
let plain  = try BiometricVault.decrypt(sealed, account: "notes", reason: "Unlock notes")
```

## CipherServer
```swift
// Sign a JWT (verify with CipherKit.JWTVerifier)
let token = try JWTSigner.sign(claims: ["sub": "42"], algorithm: .es256(privateKey: key))

// RSA with your private key
let plain = try RSAPrivate.decrypt(cipher, privateKey: priv)
let sig   = try RSAPrivate.sign(data, privateKey: priv)

// TLS public-key pinning
let delegate = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: ["<base64 sha256 of leaf key>"])
let session  = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

---

Created by AnhPT.
