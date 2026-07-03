//
//  Base32.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  RFC 4648 Base32 — the standard encoding for TOTP/HOTP shared secrets
//  (e.g. from `otpauth://` QR codes).

import Foundation

public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    private static let reverse: [Character: UInt8] = {
        var map: [Character: UInt8] = [:]
        for (index, char) in alphabet.enumerated() { map[char] = UInt8(index) }
        return map
    }()

    public static func encode(_ data: Data) -> String {
        var output = ""
        var buffer: UInt64 = 0
        var bitsLeft = 0
        for byte in data {
            buffer = (buffer << 8) | UInt64(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                let index = Int((buffer >> UInt64(bitsLeft - 5)) & 0x1f)
                output.append(alphabet[index])
                bitsLeft -= 5
            }
        }
        if bitsLeft > 0 {
            let index = Int((buffer << UInt64(5 - bitsLeft)) & 0x1f)
            output.append(alphabet[index])
        }
        return output
    }

    public static func decode(_ string: String) -> Data? {
        var buffer: UInt64 = 0
        var bitsLeft = 0
        var output = Data()
        for char in string.uppercased() where char != "=" {
            guard let value = reverse[char] else {
                if char == " " || char == "\n" { continue }
                return nil
            }
            buffer = (buffer << 5) | UInt64(value)
            bitsLeft += 5
            if bitsLeft >= 8 {
                output.append(UInt8((buffer >> UInt64(bitsLeft - 8)) & 0xff))
                bitsLeft -= 8
            }
        }
        return output
    }
}
