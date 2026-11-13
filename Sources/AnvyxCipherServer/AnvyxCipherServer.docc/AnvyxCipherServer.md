# ``AnvyxCipherServer``

Server-side / advanced crypto: JWT signing with private keys and TLS certificate
pinning.

## Overview

Pieces that need a private key or network-trust customization — signing JWTs and
pinning server certificates against known public-key hashes.

```swift
let policy = PinPolicy(hosts: ["api.example.com"], pins: [currentPin, backupPin])
let delegate = PinnedSessionDelegate(policy: policy)
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

Pins are `base64(SHA-256(SubjectPublicKeyInfo))` — see ``SPKIPin``. Ship a
backup pin next to the current one, and when rotating add the new pin in a
release **before** removing the old one (details on ``PinPolicy``).

## Topics

- ``JWTSigner``
- ``RSAPrivate``
- ``PinnedSessionDelegate``
- ``PinPolicy``
- ``SPKIPin``
