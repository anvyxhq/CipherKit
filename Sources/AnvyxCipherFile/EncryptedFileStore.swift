//
//  EncryptedFileStore.swift
//  CipherFile
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit
import AnvyxCipherKit

/// Streaming, chunked file encryption — encrypt/decrypt large files without
/// loading them fully into memory. Each chunk is a self-contained AES-GCM box
/// written as `[UInt32 length][sealed chunk]`.
///
/// Output is written **atomically**: data goes to a temporary file next to the
/// destination and is renamed into place only after every chunk succeeded, so
/// a failure (wrong key, truncated input, full disk) never leaves a partial
/// file or damages an existing one.
///
/// ```swift
/// try EncryptedFileStore.encrypt(fileAt: source, to: vault, using: key,
///                                options: .init(excludeFromBackup: true))
/// ```
public enum EncryptedFileStore {

    /// Data-protection class of a written file.
    public enum FileProtection: Sendable {
        /// Readable only while the device is unlocked.
        case complete
        /// Readable after the first unlock following a boot — works for
        /// background tasks on a locked device.
        case completeUntilFirstUserAuthentication
        /// A file opened while unlocked stays usable after the device locks.
        case completeUnlessOpen
        /// No data protection.
        case none

        var value: FileProtectionType {
            switch self {
            case .complete: return .complete
            case .completeUntilFirstUserAuthentication: return .completeUntilFirstUserAuthentication
            case .completeUnlessOpen: return .completeUnlessOpen
            case .none: return .none
            }
        }
    }

    /// How an output file is stored.
    public struct WriteOptions: Sendable {
        /// Data-protection class; `nil` picks the default of the operation
        /// (see ``EncryptedFileStore/encrypt(fileAt:to:using:chunkSize:options:)``
        /// and ``EncryptedFileStore/decrypt(fileAt:to:using:options:)``).
        public var protection: FileProtection?
        /// Keep the file out of iCloud and local device backups.
        public var excludeFromBackup: Bool

        public init(protection: FileProtection? = nil, excludeFromBackup: Bool = false) {
            self.protection = protection
            self.excludeFromBackup = excludeFromBackup
        }
    }

    public static let defaultChunkSize = 1 << 20   // 1 MB

    /// Encrypts `source` into `destination`.
    ///
    /// Default protection: ``FileProtection/completeUntilFirstUserAuthentication``
    /// — the content is already encrypted, and this keeps background writes
    /// working.
    public static func encrypt(fileAt source: URL, to destination: URL,
                               using key: SymmetricKey, chunkSize: Int = defaultChunkSize,
                               options: WriteOptions = WriteOptions()) throws {
        precondition(chunkSize > 0, "chunkSize must be positive")
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        try writeAtomically(to: destination, options: options,
                            defaultProtection: .completeUntilFirstUserAuthentication) { output in
            while let chunk = try input.read(upToCount: chunkSize), !chunk.isEmpty {
                let sealed = try AESGCM.seal(chunk, using: key)
                try output.write(contentsOf: lengthPrefix(sealed.count))
                try output.write(contentsOf: sealed)
            }
        }
    }

    /// Decrypts `source` into `destination`.
    ///
    /// Default protection: ``FileProtection/completeUntilFirstUserAuthentication``
    /// (the system default), so decrypting keeps working while the device is
    /// locked. The output is plaintext: pass ``FileProtection/complete`` in
    /// `options` when the file is only needed while the device is unlocked.
    public static func decrypt(fileAt source: URL, to destination: URL, using key: SymmetricKey,
                               options: WriteOptions = WriteOptions()) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        try writeAtomically(to: destination, options: options, defaultProtection: .completeUntilFirstUserAuthentication) { output in
            while let header = try input.read(upToCount: 4), !header.isEmpty {
                guard header.count == 4 else { throw CipherError.sealFailed }
                let length = header.reduce(0) { ($0 << 8) | Int($1) }
                guard let sealed = try input.read(upToCount: length), sealed.count == length else {
                    throw CipherError.sealFailed
                }
                try output.write(contentsOf: try AESGCM.open(sealed, using: key))
            }
        }
    }

    // MARK: - Atomic output

    /// Runs `body` against a temporary sibling of `destination`, then renames
    /// it into place. The temporary file is removed when anything fails.
    private static func writeAtomically(to destination: URL, options: WriteOptions,
                                        defaultProtection: FileProtection,
                                        _ body: (FileHandle) throws -> Void) throws {
        let protection = (options.protection ?? defaultProtection).value
        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil,
                                             attributes: [.protectionKey: protection]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: temporary.path])
        }
        do {
            let output = try FileHandle(forWritingTo: temporary)
            do {
                try body(output)
                try output.synchronize()
                try output.close()
            } catch {
                try? output.close()
                throw error
            }
            // rename(2) replaces an existing destination in a single step.
            guard rename(temporary.path, destination.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
        if options.excludeFromBackup {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var url = destination
            try url.setResourceValues(values)
        }
    }

    private static func lengthPrefix(_ count: Int) -> Data {
        let value = UInt32(count)
        return Data([UInt8(value >> 24 & 0xff), UInt8(value >> 16 & 0xff),
                     UInt8(value >> 8 & 0xff), UInt8(value & 0xff)])
    }
}
