//
//  OTP.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238) — build an
//  authenticator (2FA) entirely on-device.

import Foundation
import CryptoKit

public enum OTPAlgorithm {
    case sha1, sha256, sha512

    public init?(name: String) {
        switch name.uppercased() {
        case "SHA1": self = .sha1
        case "SHA256": self = .sha256
        case "SHA512": self = .sha512
        default: return nil
        }
    }
    public var name: String {
        switch self { case .sha1: "SHA1"; case .sha256: "SHA256"; case .sha512: "SHA512" }
    }

    func hmac(_ message: Data, key: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        switch self {
        case .sha1:   return Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetricKey))
        case .sha256: return Data(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey))
        case .sha512: return Data(HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey))
        }
    }
}

/// HMAC-based one-time password (RFC 4226).
public enum HOTP {
    public static func code(secret: Data, counter: UInt64,
                            digits: Int = 6, algorithm: OTPAlgorithm = .sha1) -> String {
        var bigEndianCounter = counter.bigEndian
        let counterData = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }
        let hash = algorithm.hmac(counterData, key: secret)

        let offset = Int(hash[hash.count - 1] & 0x0f)
        let binary = (UInt32(hash[offset] & 0x7f) << 24)
            | (UInt32(hash[offset + 1]) << 16)
            | (UInt32(hash[offset + 2]) << 8)
            | UInt32(hash[offset + 3])
        let modulo = UInt32(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)d", binary % modulo)
    }
}

/// Time-based one-time password (RFC 6238).
public enum TOTP {
    public static func code(secret: Data, date: Date = Date(), period: TimeInterval = 30,
                            digits: Int = 6, algorithm: OTPAlgorithm = .sha1) -> String {
        let counter = UInt64(date.timeIntervalSince1970 / period)
        return HOTP.code(secret: secret, counter: counter, digits: digits, algorithm: algorithm)
    }

    /// Seconds remaining until the current code rolls over.
    public static func secondsRemaining(date: Date = Date(), period: TimeInterval = 30) -> Int {
        Int(period - date.timeIntervalSince1970.truncatingRemainder(dividingBy: period))
    }
}
