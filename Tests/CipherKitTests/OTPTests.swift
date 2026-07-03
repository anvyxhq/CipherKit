//
//  OTPTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
@testable import CipherKit

final class OTPTests: XCTestCase {

    // RFC 4226 / 6238 test secret: ASCII "12345678901234567890".
    private let secret = Data("12345678901234567890".utf8)

    func testHOTPRFC4226Vectors() {
        XCTAssertEqual(HOTP.code(secret: secret, counter: 0), "755224")
        XCTAssertEqual(HOTP.code(secret: secret, counter: 1), "287082")
        XCTAssertEqual(HOTP.code(secret: secret, counter: 2), "359152")
    }

    func testTOTPRFC6238Vector() {
        // SHA-1, 8 digits, T = 59s → 94287082.
        let code = TOTP.code(secret: secret, date: Date(timeIntervalSince1970: 59), digits: 8, algorithm: .sha1)
        XCTAssertEqual(code, "94287082")
    }

    func testBase32RoundTripAndVector() {
        XCTAssertEqual(Base32.encode(Data("foobar".utf8)), "MZXW6YTBOI")
        XCTAssertEqual(Base32.decode("MZXW6YTBOI"), Data("foobar".utf8))
        let random = CryptoRandom.bytes(20)
        XCTAssertEqual(Base32.decode(Base32.encode(random)), random)
    }
}
