//
//  CipherKitLocalTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import CipherKit

final class CipherKitLocalTests: XCTestCase {

    struct Profile: Codable, Equatable { let name: String; let age: Int }

    func testSecretBoxDataRoundTrip() throws {
        let key = AESGCM.randomKey()
        let data = Data("at rest".utf8)
        XCTAssertEqual(try SecretBox.decrypt(SecretBox.encrypt(data, using: key), using: key), data)
    }

    func testSecretBoxCodableRoundTrip() throws {
        let key = AESGCM.randomKey()
        let profile = Profile(name: "AnhPT", age: 30)
        let sealed = try SecretBox.encrypt(profile, using: key)
        XCTAssertEqual(try SecretBox.decrypt(Profile.self, from: sealed, using: key), profile)
    }

    func testPasscodeHashVerify() {
        let hashed = Passcode.hash("1234", rounds: 1000)
        XCTAssertTrue(Passcode.verify("1234", against: hashed))
        XCTAssertFalse(Passcode.verify("0000", against: hashed))
        // Hashed is Codable (persist it, not the passcode)
        XCTAssertNoThrow(try JSONEncoder().encode(hashed))
    }

    func testSecureEnclaveAvailabilityCallable() {
        // On Simulator this is false; just verify the API is callable.
        _ = SecureEnclaveSigner.isAvailable
    }
}
