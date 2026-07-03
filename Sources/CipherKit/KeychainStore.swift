//
//  KeychainStore.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import Security
import CryptoKit

/// Where a keychain item is readable.
public enum KeychainAccessibility {
    case whenUnlocked
    case afterFirstUnlock
    case whenUnlockedThisDeviceOnly
    case afterFirstUnlockThisDeviceOnly

    var value: CFString {
        switch self {
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock
        case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }
}

/// Service-scoped Keychain storage for secrets and crypto keys (no biometrics —
/// see `CipherBiometric.BiometricVault` for a Face ID-gated variant).
public struct KeychainStore {
    public enum Failure: Error { case status(OSStatus) }

    private let service: String

    public init(service: String) { self.service = service }

    // MARK: - Raw data

    public func set(_ data: Data, for account: String,
                    accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(query as CFDictionary)
        var attributes = query
        attributes[kSecValueData] = data
        attributes[kSecAttrAccessible] = accessibility.value
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure.status(status) }
    }

    public func data(for account: String) -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    public func remove(for account: String) {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ] as CFDictionary)
    }

    public func removeAll() {
        SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service] as CFDictionary)
    }

    // MARK: - Typed convenience

    public func setKey(_ key: SymmetricKey, for account: String,
                       accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly) throws {
        try set(key.withUnsafeBytes { Data($0) }, for: account, accessibility: accessibility)
    }

    public func key(for account: String) -> SymmetricKey? {
        data(for: account).map { SymmetricKey(data: $0) }
    }

    public func string(for account: String) -> String? {
        data(for: account).flatMap { String(data: $0, encoding: .utf8) }
    }
}
