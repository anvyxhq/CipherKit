//
//  ClientSideTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
@testable import AnvyxCipherKit

final class ClientSideTests: XCTestCase {

    func testOTPAuthURIParseAndCode() {
        // secret "12345678901234567890" base32-encoded, TOTP SHA1 8 digits.
        let base32 = Base32.encode(Data("12345678901234567890".utf8))
        let uri = "otpauth://totp/Anvyx:anhpt?secret=\(base32)&issuer=Anvyx&digits=8&period=30&algorithm=SHA1"
        guard let parsed = OTPAuthURI(uri) else { return XCTFail("parse failed") }
        XCTAssertEqual(parsed.kind, .totp)
        XCTAssertEqual(parsed.issuer, "Anvyx")
        XCTAssertEqual(parsed.digits, 8)
        XCTAssertEqual(parsed.currentCode(date: Date(timeIntervalSince1970: 59)), "94287082")
    }

    func testOTPAuthURIRoundTrip() {
        let original = OTPAuthURI(kind: .totp, label: "acc", issuer: "Iss",
                                  secret: Data("secret!!".utf8), digits: 6)
        guard let reparsed = OTPAuthURI(original.uriString) else { return XCTFail() }
        XCTAssertEqual(reparsed.secret, original.secret)
        XCTAssertEqual(reparsed.digits, 6)
    }

    func testLockoutEscalates() {
        let policy = LockoutPolicy(maxAttempts: 3, baseLockout: 10, multiplier: 2)
        var state = LockoutState()
        let now = Date(timeIntervalSince1970: 1000)
        state = PasscodeThrottle.recordFailure(state, policy: policy, now: now)  // 1
        state = PasscodeThrottle.recordFailure(state, policy: policy, now: now)  // 2
        XCTAssertFalse(PasscodeThrottle.isLockedOut(state, now: now))
        state = PasscodeThrottle.recordFailure(state, policy: policy, now: now)  // 3 → lock 10s
        XCTAssertTrue(PasscodeThrottle.isLockedOut(state, now: now))
        XCTAssertEqual(PasscodeThrottle.remainingLockout(state, now: now), 10, accuracy: 0.5)
        state = PasscodeThrottle.recordSuccess(state)
        XCTAssertFalse(PasscodeThrottle.isLockedOut(state, now: now))
        XCTAssertEqual(state.failedAttempts, 0)
    }

    func testPasswordGeneratorPolicy() {
        let pw = PasswordGenerator.generate(.init(length: 20))
        XCTAssertEqual(pw.count, 20)
        XCTAssertTrue(pw.contains { $0.isLowercase })
        XCTAssertTrue(pw.contains { $0.isUppercase })
        XCTAssertTrue(pw.contains { $0.isNumber })
        // digits-only policy
        let pin = PasswordGenerator.generate(.init(length: 6, lowercase: false, uppercase: false, digits: true, symbols: false))
        XCTAssertTrue(pin.allSatisfy { $0.isNumber })
    }
}
