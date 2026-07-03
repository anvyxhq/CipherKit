//
//  SecretBox.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

/// Encrypt data / `Codable` values at rest (AES-GCM). Handy for storing local
/// models securely — no backend required.
public enum SecretBox {
    public static func encrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        try AESGCM.seal(data, using: key)
    }
    public static func decrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        try AESGCM.open(data, using: key)
    }

    /// Encrypt a `Codable` value (JSON-encoded).
    public static func encrypt<T: Encodable>(_ value: T, using key: SymmetricKey,
                                             encoder: JSONEncoder = JSONEncoder()) throws -> Data {
        try encrypt(encoder.encode(value), using: key)
    }

    /// Decrypt and decode a `Codable` value.
    public static func decrypt<T: Decodable>(_ type: T.Type, from data: Data, using key: SymmetricKey,
                                             decoder: JSONDecoder = JSONDecoder()) throws -> T {
        try decoder.decode(T.self, from: decrypt(data, using: key))
    }
}
