//
//  BiometricKey.swift
//  CipherBiometric
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit
import LocalAuthentication
import AnvyxCipherKit

/// A Secure Enclave P-256 key whose **use is gated by Face ID / Touch ID**.
/// The private key never leaves the enclave; each `sign` triggers a biometric
/// prompt. Persist `dataRepresentation` and reload with an `LAContext`.
public enum BiometricKey {

    public enum Failure: Error { case accessControlFailed, biometricsUnavailable }

    /// Whether biometric authentication is currently possible.
    public static func isAvailable(_ context: LAContext = LAContext()) -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// Generate a biometry-gated Secure Enclave signing key.
    public static func generate() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        ) else { throw Failure.accessControlFailed }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    }

    /// Reload a persisted key; `reason` is shown in the biometric prompt.
    public static func load(from dataRepresentation: Data,
                            reason: String,
                            context: LAContext = LAContext()) throws -> SecureEnclave.P256.Signing.PrivateKey {
        context.localizedReason = reason
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation,
                                                         authenticationContext: context)
    }

    /// Sign (prompts for biometrics). Returns a DER-encoded ECDSA signature.
    public static func sign(_ data: Data, with key: SecureEnclave.P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: data).derRepresentation
    }

    /// Verify a signature with the public key (no biometrics needed).
    public static func verify(_ derSignature: Data, of data: Data, with publicKey: P256.Signing.PublicKey) -> Bool {
        ECDSAP256.verify(derSignature, of: data, with: publicKey)
    }
}
