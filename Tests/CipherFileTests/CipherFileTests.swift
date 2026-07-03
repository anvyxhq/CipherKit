//
//  CipherFileTests.swift
//  CipherFile
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
import CipherKit
@testable import CipherFile

final class CipherFileTests: XCTestCase {

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    func testEncryptDecryptFileRoundTrip() throws {
        let key = AESGCM.randomKey()
        let src = tempURL(), enc = tempURL(), dec = tempURL()
        defer { [src, enc, dec].forEach { try? FileManager.default.removeItem(at: $0) } }

        // ~2.5 chunks of data to exercise chunking.
        let payload = Data((0..<(2_500_000)).map { UInt8($0 & 0xff) })
        try payload.write(to: src)

        try EncryptedFileStore.encrypt(fileAt: src, to: enc, using: key, chunkSize: 1_000_000)
        XCTAssertNotEqual(try Data(contentsOf: enc), payload)   // actually encrypted
        try EncryptedFileStore.decrypt(fileAt: enc, to: dec, using: key)
        XCTAssertEqual(try Data(contentsOf: dec), payload)
    }

    func testFileHashMatchesInMemory() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let payload = Data((0..<300_000).map { UInt8($0 & 0xff) })
        try payload.write(to: url)
        XCTAssertEqual(try FileHash.sha256(fileAt: url, chunkSize: 100_000), Hashing.sha256(payload))
    }

    func testKeyRotationReencryptData() throws {
        let oldKey = AESGCM.randomKey(), newKey = AESGCM.randomKey()
        let sealed = try SecretBox.encrypt(Data("secret".utf8), using: oldKey)
        let rotated = try KeyRotation.reencrypt(sealed, from: oldKey, to: newKey)
        XCTAssertThrowsError(try SecretBox.decrypt(rotated, using: oldKey))       // old key no longer works
        XCTAssertEqual(try SecretBox.decrypt(rotated, using: newKey), Data("secret".utf8))
    }

    func testKeyRotationReencryptFile() throws {
        let oldKey = AESGCM.randomKey(), newKey = AESGCM.randomKey()
        let src = tempURL(), enc = tempURL(), dec = tempURL()
        defer { [src, enc, dec].forEach { try? FileManager.default.removeItem(at: $0) } }
        let payload = Data("rotate me".utf8)
        try payload.write(to: src)
        try EncryptedFileStore.encrypt(fileAt: src, to: enc, using: oldKey)
        try KeyRotation.reencryptFile(at: enc, from: oldKey, to: newKey)
        try EncryptedFileStore.decrypt(fileAt: enc, to: dec, using: newKey)
        XCTAssertEqual(try Data(contentsOf: dec), payload)
    }
}
