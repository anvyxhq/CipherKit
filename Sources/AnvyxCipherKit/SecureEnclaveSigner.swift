//
//  SecureEnclaveSigner.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

/// Hardware-backed P-256 signing using the Secure Enclave. The private key
/// never leaves the chip; persist `dataRepresentation` (an encrypted blob) to
/// recreate it later. Fully on-device — no backend needed.
///
/// - Note: The Secure Enclave is only available on real devices, so
///   ``isAvailable`` is `false` on the Simulator.
public enum SecureEnclaveSigner {

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Generate a new Secure Enclave signing key.
    public static func generateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey()
    }

    /// Recreate a key from its persisted representation.
    public static func key(from dataRepresentation: Data) throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
    }

    /// Sign data; returns a DER-encoded ECDSA signature.
    public static func sign(_ data: Data, with key: SecureEnclave.P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: data).derRepresentation
    }

    /// Verify a DER signature against the key's public key (verifiable anywhere).
    public static func verify(_ derSignature: Data, of data: Data,
                              with publicKey: P256.Signing.PublicKey) -> Bool {
        ECDSAP256.verify(derSignature, of: data, with: publicKey)
    }
}
