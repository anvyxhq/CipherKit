//
//  EnvelopeAADTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import CipherKit

final class EnvelopeAADTests: XCTestCase {

    func testAESGCMWithAAD() throws {
        let key = AESGCM.randomKey()
        let data = Data("body".utf8)
        let aad = Data("v1|header".utf8)
        let sealed = try AESGCM.seal(data, using: key, authenticating: aad)
        XCTAssertEqual(try AESGCM.open(sealed, using: key, authenticating: aad), data)
        XCTAssertThrowsError(try AESGCM.open(sealed, using: key, authenticating: Data("v2".utf8)))
    }

    func testEnvelopeSealOpenAndRewrap() throws {
        let master1 = AESGCM.randomKey(), master2 = AESGCM.randomKey()
        let payload = Data("large payload".utf8)
        let sealed = try Envelope.seal(payload, master: master1)
        XCTAssertEqual(try Envelope.open(sealed, master: master1), payload)

        let rewrapped = try Envelope.rewrap(sealed, from: master1, to: master2)
        XCTAssertEqual(rewrapped.ciphertext, sealed.ciphertext)          // payload untouched
        XCTAssertThrowsError(try Envelope.open(rewrapped, master: master1))  // old master invalid
        XCTAssertEqual(try Envelope.open(rewrapped, master: master2), payload)
    }

    func testConstantTimeEqual() {
        XCTAssertTrue(ConstantTime.equal(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(ConstantTime.equal(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(ConstantTime.equal(Data([1, 2]), Data([1, 2, 3])))
    }

    func testEncryptedDefaultsRoundTrip() throws {
        struct Prefs: Codable, Equatable { let token: String; let count: Int }
        let defaults = UserDefaults(suiteName: "cipherkit.tests.\(UUID().uuidString)")!
        let store = EncryptedDefaults(key: AESGCM.randomKey(), defaults: defaults)
        let prefs = Prefs(token: "abc", count: 3)
        try store.set(prefs, forKey: "prefs")
        // stored value is ciphertext, not the plaintext
        XCTAssertNotNil(defaults.data(forKey: "prefs"))
        XCTAssertEqual(try store.value(Prefs.self, forKey: "prefs"), prefs)
        store.removeValue(forKey: "prefs")
        XCTAssertNil(try store.value(Prefs.self, forKey: "prefs"))
    }
}
