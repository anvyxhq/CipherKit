//
//  CipherKitTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import CipherKit

final class CipherKitTests: XCTestCase {

    func testAESGCMRoundTrip() throws {
        let key = AESGCM.randomKey()
        let plaintext = Data("secret message".utf8)
        let sealed = try AESGCM.seal(plaintext, using: key)
        XCTAssertNotEqual(sealed, plaintext)
        XCTAssertEqual(try AESGCM.open(sealed, using: key), plaintext)
    }

    func testAESGCMWrongKeyFails() throws {
        let sealed = try AESGCM.seal(Data("x".utf8), using: AESGCM.randomKey())
        XCTAssertThrowsError(try AESGCM.open(sealed, using: AESGCM.randomKey()))
    }

    func testSHA256KnownVector() {
        // SHA-256("abc")
        XCTAssertEqual("abc".sha256Hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    func testHMACDeterministic() {
        let key = Data("key".utf8), msg = Data("data".utf8)
        XCTAssertEqual(Hashing.hmacSHA256(msg, key: key), Hashing.hmacSHA256(msg, key: key))
    }

    func testRandomStringLength() {
        XCTAssertEqual(CryptoRandom.string(length: 16).count, 16)
        XCTAssertEqual(CryptoRandom.bytes(12).count, 12)
    }

    func testCBORDecodesMapArrayText() {
        // {"a": 1}
        XCTAssertEqual(CBOR.decode(Data([0xA1, 0x61, 0x61, 0x01])), .map(["a": .unsigned(1)]))
        // [1, 2]
        XCTAssertEqual(CBOR.decode(Data([0x82, 0x01, 0x02])), .array([.unsigned(1), .unsigned(2)]))
        // "IETF"
        XCTAssertEqual(CBOR.decode(Data([0x64, 0x49, 0x45, 0x54, 0x46])), .text("IETF"))
    }

    func testRSAEncryptWithGeneratedKey() throws {
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicDER = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return XCTFail("keygen failed")
        }
        let cipher = try RSA.encrypt(Data("hi".utf8), publicKeyDER: publicDER)
        XCTAssertFalse(cipher.isEmpty)
        // round-trip via private key
        let clear = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, cipher as CFData, &error) as Data?
        XCTAssertEqual(clear, Data("hi".utf8))
    }
}
