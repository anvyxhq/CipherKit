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
public enum EncryptedFileStore {

    public static let defaultChunkSize = 1 << 20   // 1 MB

    public static func encrypt(fileAt source: URL, to destination: URL,
                               using key: SymmetricKey, chunkSize: Int = defaultChunkSize) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }

        while case let chunk = input.readData(ofLength: chunkSize), !chunk.isEmpty {
            let sealed = try AESGCM.seal(chunk, using: key)
            output.write(lengthPrefix(sealed.count))
            output.write(sealed)
        }
    }

    public static func decrypt(fileAt source: URL, to destination: URL, using key: SymmetricKey) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }

        while case let header = input.readData(ofLength: 4), !header.isEmpty {
            guard header.count == 4 else { throw CipherError.sealFailed }
            let length = header.reduce(0) { ($0 << 8) | Int($1) }
            let sealed = input.readData(ofLength: length)
            guard sealed.count == length else { throw CipherError.sealFailed }
            output.write(try AESGCM.open(sealed, using: key))
        }
    }

    private static func lengthPrefix(_ count: Int) -> Data {
        let value = UInt32(count)
        return Data([UInt8(value >> 24 & 0xff), UInt8(value >> 16 & 0xff),
                     UInt8(value >> 8 & 0xff), UInt8(value & 0xff)])
    }
}
