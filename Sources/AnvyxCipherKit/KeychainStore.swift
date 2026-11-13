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
public enum KeychainAccessibility: Sendable {
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
///
/// ```swift
/// let store = KeychainStore(service: "com.app.secrets", accessibility: .whenUnlockedThisDeviceOnly)
/// try store.set(token, for: "session")
/// do {
///     let token = try store.requireData(for: "session")
/// } catch KeychainStore.Failure.interactionNotAllowed {
///     // Device is locked — the item exists, try again after unlock.
/// } catch KeychainStore.Failure.itemNotFound {
///     // Nothing stored.
/// }
/// ```
public struct KeychainStore {
    public enum Failure: Error, Equatable {
        /// No item is stored for the account.
        case itemNotFound
        /// The item exists but cannot be read or written right now — typically
        /// the device is locked and the item's accessibility does not allow it.
        case interactionNotAllowed
        /// Any other Security framework status.
        case status(OSStatus)

        init(_ status: OSStatus) {
            switch status {
            case errSecItemNotFound: self = .itemNotFound
            case errSecInteractionNotAllowed: self = .interactionNotAllowed
            default: self = .status(status)
            }
        }
    }

    private let service: String
    /// Accessibility applied by `set` when the call does not pass one.
    public let accessibility: KeychainAccessibility

    /// - Parameters:
    ///   - service: Namespace for the items of this store.
    ///   - accessibility: Default for new and updated items. The
    ///     `…ThisDeviceOnly` values keep items out of backups and device
    ///     migration.
    public init(service: String, accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly) {
        self.service = service
        self.accessibility = accessibility
    }

    // MARK: - Queries

    func itemQuery(account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
    }

    func readQuery(account: String) -> [CFString: Any] {
        var query = itemQuery(account: account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        return query
    }

    func valueAttributes(_ data: Data, accessibility: KeychainAccessibility?) -> [CFString: Any] {
        [
            kSecValueData: data,
            kSecAttrAccessible: (accessibility ?? self.accessibility).value,
        ]
    }

    // MARK: - Raw data

    /// Stores `data`, replacing any existing value in place: the item is
    /// updated, and only added when it does not exist yet, so a failed write
    /// never loses the previous value.
    ///
    /// - Parameter accessibility: Overrides the store's default for this item.
    public func set(_ data: Data, for account: String,
                    accessibility: KeychainAccessibility? = nil) throws {
        let query = itemQuery(account: account)
        let attributes = valueAttributes(data, accessibility: accessibility)
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure(status) }
    }

    /// Reads the value, telling apart "nothing stored"
    /// (``Failure/itemNotFound``) from "stored but not readable now"
    /// (``Failure/interactionNotAllowed``, e.g. device locked).
    public func requireData(for account: String) throws -> Data {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(readQuery(account: account) as CFDictionary, &result)
        guard status == errSecSuccess else { throw Failure(status) }
        guard let data = result as? Data else { throw Failure.status(errSecDecode) }
        return data
    }

    /// Reads the value, or `nil` on **any** failure. Use
    /// ``requireData(for:)`` when a locked device must not be mistaken for a
    /// missing item.
    public func data(for account: String) -> Data? {
        try? requireData(for: account)
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
                       accessibility: KeychainAccessibility? = nil) throws {
        try set(key.withUnsafeBytes { Data($0) }, for: account, accessibility: accessibility)
    }

    /// Throwing variant of ``key(for:)`` — see ``requireData(for:)``.
    public func requireKey(for account: String) throws -> SymmetricKey {
        SymmetricKey(data: try requireData(for: account))
    }

    public func key(for account: String) -> SymmetricKey? {
        data(for: account).map { SymmetricKey(data: $0) }
    }

    public func string(for account: String) -> String? {
        data(for: account).flatMap { String(data: $0, encoding: .utf8) }
    }
}
