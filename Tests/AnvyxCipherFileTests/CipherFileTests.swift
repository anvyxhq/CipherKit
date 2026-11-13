//
//  CipherFileTests.swift
//  CipherFile
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
import AnvyxCipherKit
@testable import AnvyxCipherFile

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

    private func siblings(of url: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path)
            .filter { $0.contains(url.lastPathComponent) }
    }

    func testFailedDecryptKeepsExistingDestinationAndLeavesNoTemp() throws {
        let key = AESGCM.randomKey()
        let src = tempURL(), enc = tempURL(), dec = tempURL()
        defer { [src, enc, dec].forEach { try? FileManager.default.removeItem(at: $0) } }
        try Data((0..<5_000).map { UInt8($0 & 0xff) }).write(to: src)
        try EncryptedFileStore.encrypt(fileAt: src, to: enc, using: key, chunkSize: 1_000)

        let existing = Data("keep me".utf8)
        try existing.write(to: dec)
        XCTAssertThrowsError(try EncryptedFileStore.decrypt(fileAt: enc, to: dec, using: AESGCM.randomKey()))
        XCTAssertEqual(try Data(contentsOf: dec), existing)
        XCTAssertEqual(try siblings(of: dec), [dec.lastPathComponent])

        // Truncated ciphertext: first chunks are valid, the last one is cut.
        let truncated = try Data(contentsOf: enc).dropLast(10)
        try truncated.write(to: enc)
        XCTAssertThrowsError(try EncryptedFileStore.decrypt(fileAt: enc, to: dec, using: key))
        XCTAssertEqual(try Data(contentsOf: dec), existing)
        XCTAssertEqual(try siblings(of: dec), [dec.lastPathComponent])
    }

    func testEncryptReplacesExistingDestination() throws {
        let key = AESGCM.randomKey()
        let src = tempURL(), enc = tempURL(), dec = tempURL()
        defer { [src, enc, dec].forEach { try? FileManager.default.removeItem(at: $0) } }
        try Data("old".utf8).write(to: enc)
        try Data("payload".utf8).write(to: src)
        try EncryptedFileStore.encrypt(fileAt: src, to: enc, using: key)
        try EncryptedFileStore.decrypt(fileAt: enc, to: dec, using: key)
        XCTAssertEqual(try Data(contentsOf: dec), Data("payload".utf8))
        XCTAssertEqual(try siblings(of: enc), [enc.lastPathComponent])
    }

    func testMissingSourceCreatesNothing() {
        let enc = tempURL()
        XCTAssertThrowsError(try EncryptedFileStore.encrypt(fileAt: tempURL(), to: enc, using: AESGCM.randomKey()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: enc.path))
    }

    func testExcludeFromBackupOption() throws {
        let key = AESGCM.randomKey()
        let src = tempURL(), plain = tempURL(), excluded = tempURL()
        defer { [src, plain, excluded].forEach { try? FileManager.default.removeItem(at: $0) } }
        try Data("payload".utf8).write(to: src)

        try EncryptedFileStore.encrypt(fileAt: src, to: plain, using: key)
        try EncryptedFileStore.encrypt(fileAt: src, to: excluded, using: key,
                                       options: .init(protection: .complete, excludeFromBackup: true))
        XCTAssertNotEqual(try plain.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        XCTAssertEqual(try excluded.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)

        // Rotation keeps the option.
        try KeyRotation.reencryptFile(at: plain, from: key, to: AESGCM.randomKey(),
                                      options: .init(excludeFromBackup: true))
        XCTAssertEqual(try plain.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
    }

    func testProtectionMapping() {
        XCTAssertEqual(EncryptedFileStore.FileProtection.complete.value, .complete)
        XCTAssertEqual(EncryptedFileStore.FileProtection.completeUntilFirstUserAuthentication.value,
                       .completeUntilFirstUserAuthentication)
        XCTAssertEqual(EncryptedFileStore.FileProtection.completeUnlessOpen.value, .completeUnlessOpen)
        XCTAssertEqual(EncryptedFileStore.FileProtection.none.value, FileProtectionType.none)
        XCTAssertNil(EncryptedFileStore.WriteOptions().protection)
        XCTAssertFalse(EncryptedFileStore.WriteOptions().excludeFromBackup)
    }
}
