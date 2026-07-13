# ``AnvyxCipherKit``

Practical cryptography on CryptoKit: symmetric & public-key crypto, hashing, key
derivation, Keychain, OTP, passcodes, password tools, JWT, and encoding.

## Overview

High-level, misuse-resistant wrappers over CryptoKit and the Security framework —
authenticated encryption, signing, and secure storage without the boilerplate.

```swift
let key = AESGCM.randomKey()
let sealed = try AESGCM.seal(data, using: key)
let plain  = try AESGCM.open(sealed, using: key)

let store = KeychainStore(service: "com.app.secrets")
try store.setKey(key, for: "session")
```

## Topics

### Symmetric Encryption
- ``AESGCM``
- ``ChaChaPoly20``
- ``SecretBox``
- ``Envelope``
- ``EncryptedDefaults``
- ``AESKeyManager``

### Keys & Signing
- ``RSA``
- ``ECDSAP256``
- ``Ed25519``
- ``KeyAgreement``
- ``KeyDerivation``
- ``SecureEnclaveSigner``

### Hashing & Randomness
- ``Hashing``
- ``ConstantTime``
- ``CryptoRandom``

### Keychain
- ``KeychainStore``
- ``KeychainAccessibility``

### One-Time Passwords
- ``TOTP``
- ``HOTP``
- ``OTPAlgorithm``
- ``OTPAuthURI``

### Passcodes & Passwords
- ``Passcode``
- ``PasscodeThrottle``
- ``LockoutPolicy``
- ``PasswordGenerator``

### Tokens & Encoding
- ``JWT``
- ``JWTVerifier``
- ``Base32``
- ``CBOR``
