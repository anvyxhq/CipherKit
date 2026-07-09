//
//  KeyRotation.swift
//  CipherFile
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit
import AnvyxCipherKit

/// Re-encrypt data / files from an old key to a new key (key rotation).
public enum KeyRotation {

    /// Re-encrypt a `SecretBox` blob under a new key.
    public static func reencrypt(_ sealed: Data, from oldKey: SymmetricKey, to newKey: SymmetricKey) throws -> Data {
        try SecretBox.encrypt(SecretBox.decrypt(sealed, using: oldKey), using: newKey)
    }

    /// Re-encrypt a chunked ``EncryptedFileStore`` file to a new key, atomically
    /// (writes to a temp file, then replaces the original).
    public static func reencryptFile(at url: URL, from oldKey: SymmetricKey, to newKey: SymmetricKey,
                                     chunkSize: Int = EncryptedFileStore.defaultChunkSize) throws {
        let plainURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rotate-plain-\(UUID().uuidString)")
        let cipherURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rotate-cipher-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(at: plainURL)
            try? FileManager.default.removeItem(at: cipherURL)
        }
        try EncryptedFileStore.decrypt(fileAt: url, to: plainURL, using: oldKey)
        try EncryptedFileStore.encrypt(fileAt: plainURL, to: cipherURL, using: newKey, chunkSize: chunkSize)
        _ = try FileManager.default.replaceItemAt(url, withItemAt: cipherURL)
    }
}
