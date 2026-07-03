//
//  DataEncoding.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit

public extension Data {
    /// Lowercase hex string.
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    /// Parse a hex string (even length).
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count.isMultiple(of: 2) else { return nil }
        var data = Data(capacity: chars.count / 2)
        var index = 0
        while index < chars.count {
            guard let byte = UInt8(String(chars[index...index + 1]), radix: 16) else { return nil }
            data.append(byte)
            index += 2
        }
        self = data
    }

    /// Base64URL (no padding) — used by JWT / App Attest.
    var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode Base64URL (with or without padding).
    init?(base64URLEncoded string: String) {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while !s.count.isMultiple(of: 4) { s += "=" }
        self.init(base64Encoded: s)
    }

    /// Best-effort zeroing of the underlying bytes (not optimized away).
    mutating func secureZero() {
        guard !isEmpty else { return }
        withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress { memset_s(base, buffer.count, 0, buffer.count) }
        }
    }
}

/// ChaCha20-Poly1305 authenticated encryption (alternative to AES-GCM).
public enum ChaChaPoly20 {
    public static func seal(_ data: Data, using key: SymmetricKey) throws -> Data {
        try ChaChaPoly.seal(data, using: key).combined
    }
    public static func open(_ combined: Data, using key: SymmetricKey) throws -> Data {
        try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: combined), using: key)
    }
}
