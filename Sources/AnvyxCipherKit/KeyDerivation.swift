//
//  KeyDerivation.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit
import CommonCrypto

/// Derive symmetric keys from passwords (PBKDF2) or key material (HKDF).
public enum KeyDerivation {

    /// PBKDF2-HMAC-SHA256: stretch a password into a key.
    public static func pbkdf2(password: String, salt: Data,
                              rounds: Int = 100_000, keyByteCount: Int = 32) -> SymmetricKey {
        var derived = Data(repeating: 0, count: keyByteCount)
        let passwordBytes = Array(password.utf8)
        derived.withUnsafeMutableBytes { out in
            salt.withUnsafeBytes { saltPtr in
                _ = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.map { CChar(bitPattern: $0) }, passwordBytes.count,
                    saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(rounds),
                    out.bindMemory(to: UInt8.self).baseAddress, keyByteCount)
            }
        }
        return SymmetricKey(data: derived)
    }

    /// HKDF-SHA256: derive a key from existing key material.
    public static func hkdf(from secret: SymmetricKey, salt: Data = Data(),
                            info: Data = Data(), keyByteCount: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: secret, salt: salt, info: info, outputByteCount: keyByteCount)
    }
}
