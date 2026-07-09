//
//  Signing.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

/// Ed25519 digital signatures (Curve25519).
public enum Ed25519 {
    public static func generateKey() -> Curve25519.Signing.PrivateKey { Curve25519.Signing.PrivateKey() }

    public static func sign(_ data: Data, with privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        try privateKey.signature(for: data)
    }

    public static func verify(_ signature: Data, of data: Data,
                              with publicKey: Curve25519.Signing.PublicKey) -> Bool {
        publicKey.isValidSignature(signature, for: data)
    }
}

/// ECDSA over P-256 (NIST) — DER-encoded signatures.
public enum ECDSAP256 {
    public static func generateKey() -> P256.Signing.PrivateKey { P256.Signing.PrivateKey() }

    public static func sign(_ data: Data, with privateKey: P256.Signing.PrivateKey) throws -> Data {
        try privateKey.signature(for: data).derRepresentation
    }

    public static func verify(_ derSignature: Data, of data: Data,
                              with publicKey: P256.Signing.PublicKey) -> Bool {
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: derSignature) else { return false }
        return publicKey.isValidSignature(signature, for: data)
    }
}

/// ECDH key agreement (Curve25519) → a shared symmetric key via HKDF.
public enum KeyAgreement {
    public static func generateKey() -> Curve25519.KeyAgreement.PrivateKey { Curve25519.KeyAgreement.PrivateKey() }

    public static func sharedKey(privateKey: Curve25519.KeyAgreement.PrivateKey,
                                 peerPublicKey: Curve25519.KeyAgreement.PublicKey,
                                 salt: Data = Data(), info: Data = Data(),
                                 keyByteCount: Int = 32) throws -> SymmetricKey {
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                              sharedInfo: info, outputByteCount: keyByteCount)
    }
}
