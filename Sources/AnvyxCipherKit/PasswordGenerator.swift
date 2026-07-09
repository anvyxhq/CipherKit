//
//  PasswordGenerator.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation

/// Which character classes a generated password must include.
public struct PasswordPolicy: Equatable {
    public var length: Int
    public var lowercase: Bool
    public var uppercase: Bool
    public var digits: Bool
    public var symbols: Bool

    public init(length: Int = 16, lowercase: Bool = true, uppercase: Bool = true,
                digits: Bool = true, symbols: Bool = true) {
        self.length = length; self.lowercase = lowercase; self.uppercase = uppercase
        self.digits = digits; self.symbols = symbols
    }
}

/// Generate secure random passwords (uses the system CSPRNG). Guarantees at
/// least one character from each enabled class.
public enum PasswordGenerator {
    private static let lower = Array("abcdefghijklmnopqrstuvwxyz")
    private static let upper = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    private static let digit = Array("0123456789")
    private static let symbol = Array("!@#$%^&*()-_=+[]{}")

    public static func generate(_ policy: PasswordPolicy = .init()) -> String {
        var classes: [[Character]] = []
        if policy.lowercase { classes.append(lower) }
        if policy.uppercase { classes.append(upper) }
        if policy.digits { classes.append(digit) }
        if policy.symbols { classes.append(symbol) }
        guard !classes.isEmpty, policy.length > 0 else { return "" }

        let pool = classes.flatMap { $0 }
        var characters: [Character] = []
        // Guarantee one of each enabled class (if length allows).
        for charClass in classes where characters.count < policy.length {
            characters.append(charClass.randomElement()!)
        }
        while characters.count < policy.length {
            characters.append(pool.randomElement()!)
        }
        characters.shuffle()   // Array.shuffle() uses the system CSPRNG on Apple platforms
        return String(characters)
    }
}
