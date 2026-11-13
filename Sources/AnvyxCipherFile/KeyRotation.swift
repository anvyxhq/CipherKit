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
    /// (the original is replaced only after the new file is fully written).
    ///
    /// - Parameter options: Storage of the re-encrypted file. The intermediate
    ///   plaintext always lives in a temporary file with complete protection
    ///   and is removed afterwards.
    public static func reencryptFile(at url: URL, from oldKey: SymmetricKey, to newKey: SymmetricKey,
                                     chunkSize: Int = EncryptedFileStore.defaultChunkSize,
                                     options: EncryptedFileStore.WriteOptions = .init()) throws {
        let plainURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rotate-plain-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: plainURL) }
        try EncryptedFileStore.decrypt(fileAt: url, to: plainURL, using: oldKey)
        try EncryptedFileStore.encrypt(fileAt: plainURL, to: url, using: newKey,
                                       chunkSize: chunkSize, options: options)
    }
}
