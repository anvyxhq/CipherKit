//
//  EncryptedDefaults.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

/// Store `Codable` values **encrypted at rest** in `UserDefaults` (AES-GCM).
/// Keep the key in the Keychain (`KeychainStore`) for real apps.
public final class EncryptedDefaults {
    private let defaults: UserDefaults
    private let key: SymmetricKey

    public init(key: SymmetricKey, defaults: UserDefaults = .standard) {
        self.key = key
        self.defaults = defaults
    }

    public func set<T: Encodable>(_ value: T, forKey key: String,
                                  encoder: JSONEncoder = JSONEncoder()) throws {
        let sealed = try SecretBox.encrypt(value, using: self.key, encoder: encoder)
        defaults.set(sealed, forKey: key)
    }

    public func value<T: Decodable>(_ type: T.Type = T.self, forKey key: String,
                                    decoder: JSONDecoder = JSONDecoder()) throws -> T? {
        guard let sealed = defaults.data(forKey: key) else { return nil }
        return try SecretBox.decrypt(T.self, from: sealed, using: self.key, decoder: decoder)
    }

    public func removeValue(forKey key: String) { defaults.removeObject(forKey: key) }
}
