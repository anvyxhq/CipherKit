//
//  FileHash.swift
//  CipherFile
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

/// Hash large files incrementally (streaming) without loading them into memory.
public enum FileHash {
    public static func sha256(fileAt url: URL, chunkSize: Int = 1 << 20) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while case let chunk = handle.readData(ofLength: chunkSize), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return Data(hasher.finalize())
    }

    public static func sha512(fileAt url: URL, chunkSize: Int = 1 << 20) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA512()
        while case let chunk = handle.readData(ofLength: chunkSize), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return Data(hasher.finalize())
    }
}
