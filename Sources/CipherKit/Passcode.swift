//
//  Passcode.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

/// Local PIN / passcode hashing & verification (PBKDF2 + random salt) — store
/// the ``Hashed`` value, never the passcode itself. No backend required.
public enum Passcode {

    public struct Hashed: Codable, Equatable {
        public let salt: Data
        public let hash: Data
        public let rounds: Int
    }

    public static func hash(_ passcode: String, rounds: Int = 120_000) -> Hashed {
        let salt = CryptoRandom.bytes(16)
        let key = KeyDerivation.pbkdf2(password: passcode, salt: salt, rounds: rounds)
        return Hashed(salt: salt, hash: key.withUnsafeBytes { Data($0) }, rounds: rounds)
    }

    public static func verify(_ passcode: String, against hashed: Hashed) -> Bool {
        let key = KeyDerivation.pbkdf2(password: passcode, salt: hashed.salt, rounds: hashed.rounds)
        return ConstantTime.equal(key.withUnsafeBytes { Data($0) }, hashed.hash)
    }
}
