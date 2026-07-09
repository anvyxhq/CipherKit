//
//  BiometricVault.swift
//  CipherBiometric
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import Security
import LocalAuthentication
import CryptoKit
import AnvyxCipherKit

/// A biometric-protected local vault: encrypts data with an AES key that lives
/// in the Keychain behind **Face ID / Touch ID** access control. Any access
/// (encrypt or decrypt) requires biometric authentication. Real device only.
public enum BiometricVault {

    public enum Failure: Error { case accessControlFailed, keychainError(OSStatus) }

    /// Encrypt `data` using the vault key for `account` (creating it if needed).
    public static func encrypt(_ data: Data, account: String, reason: String) throws -> Data {
        let key = try key(for: account, reason: reason)
        return try AESGCM.seal(data, using: key)
    }

    /// Decrypt data previously produced for `account` (prompts biometrics).
    public static func decrypt(_ sealed: Data, account: String, reason: String) throws -> Data {
        let key = try key(for: account, reason: reason)
        return try AESGCM.open(sealed, using: key)
    }

    /// Remove the vault key.
    public static func remove(account: String) {
        SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrAccount: account] as CFDictionary)
    }

    // MARK: - Keychain-backed, biometry-gated key

    private static func key(for account: String, reason: String) throws -> SymmetricKey {
        if let existing = try readKey(account: account, reason: reason) { return existing }
        let new = AESGCM.randomKey()
        try storeKey(new, account: account)
        return new
    }

    private static func storeKey(_ key: SymmetricKey, account: String) throws {
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, nil
        ) else { throw Failure.accessControlFailed }

        let keyData = key.withUnsafeBytes { Data($0) }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecValueData: keyData,
            kSecAttrAccessControl: access,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure.keychainError(status) }
    }

    private static func readKey(account: String, reason: String) throws -> SymmetricKey? {
        let context = LAContext()
        context.localizedReason = reason
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecUseAuthenticationContext: context,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return nil }
            return SymmetricKey(data: data)
        case errSecItemNotFound:
            return nil
        default:
            throw Failure.keychainError(status)
        }
    }
}
