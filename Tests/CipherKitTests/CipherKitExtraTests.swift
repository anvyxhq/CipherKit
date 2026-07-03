//
//  CipherKitExtraTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import CipherKit

final class CipherKitExtraTests: XCTestCase {

    private func keyData(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    func testPBKDF2Deterministic() {
        let salt = Data("salt".utf8)
        let a = KeyDerivation.pbkdf2(password: "pw", salt: salt, rounds: 1000)
        let b = KeyDerivation.pbkdf2(password: "pw", salt: salt, rounds: 1000)
        XCTAssertEqual(keyData(a), keyData(b))
        XCTAssertEqual(keyData(a).count, 32)
        let c = KeyDerivation.pbkdf2(password: "different", salt: salt, rounds: 1000)
        XCTAssertNotEqual(keyData(a), keyData(c))
    }

    func testHKDFDerives() {
        let derived = KeyDerivation.hkdf(from: AESGCM.randomKey(), info: Data("ctx".utf8))
        XCTAssertEqual(keyData(derived).count, 32)
    }

    func testEd25519SignVerify() throws {
        let key = Ed25519.generateKey()
        let data = Data("message".utf8)
        let sig = try Ed25519.sign(data, with: key)
        XCTAssertTrue(Ed25519.verify(sig, of: data, with: key.publicKey))
        XCTAssertFalse(Ed25519.verify(sig, of: Data("tampered".utf8), with: key.publicKey))
    }

    func testP256SignVerify() throws {
        let key = ECDSAP256.generateKey()
        let data = Data("message".utf8)
        let sig = try ECDSAP256.sign(data, with: key)
        XCTAssertTrue(ECDSAP256.verify(sig, of: data, with: key.publicKey))
    }

    func testECDHBothSidesAgree() throws {
        let alice = KeyAgreement.generateKey()
        let bob = KeyAgreement.generateKey()
        let salt = Data("s".utf8)
        let aliceKey = try KeyAgreement.sharedKey(privateKey: alice, peerPublicKey: bob.publicKey, salt: salt)
        let bobKey = try KeyAgreement.sharedKey(privateKey: bob, peerPublicKey: alice.publicKey, salt: salt)
        XCTAssertEqual(keyData(aliceKey), keyData(bobKey))
    }

    func testChaChaPolyRoundTrip() throws {
        let key = AESGCM.randomKey()
        let plaintext = Data("hello chacha".utf8)
        let sealed = try ChaChaPoly20.seal(plaintext, using: key)
        XCTAssertEqual(try ChaChaPoly20.open(sealed, using: key), plaintext)
    }

    func testDataHexRoundTrip() {
        let data = Data([0x00, 0x0f, 0xab, 0xff])
        XCTAssertEqual(data.hexString, "000fabff")
        XCTAssertEqual(Data(hexString: "000fabff"), data)
        XCTAssertNil(Data(hexString: "abc"))   // odd length
    }
}
