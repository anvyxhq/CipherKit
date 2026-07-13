# ``AnvyxCipherServer``

Server-side / advanced crypto: JWT signing with private keys and TLS certificate
pinning.

## Overview

Pieces that need a private key or network-trust customization — signing JWTs and
pinning server certificates against known public-key hashes.

```swift
let delegate = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: pins)
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

## Topics

- ``JWTSigner``
- ``RSAPrivate``
- ``PinnedSessionDelegate``
