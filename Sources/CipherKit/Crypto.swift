//
//  Crypto.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit
import Security

public enum CipherError: Error {
    case sealFailed, invalidKey, rsaFailed
}

/// AES-GCM authenticated encryption (Apple CryptoKit). `seal` returns the
/// combined nonce+ciphertext+tag blob that `open` consumes.
public enum AESGCM {
    public static func randomKey() -> SymmetricKey { SymmetricKey(size: .bits256) }

    public static func seal(_ data: Data, using key: SymmetricKey) throws -> Data {
        guard let combined = try AES.GCM.seal(data, using: key).combined else { throw CipherError.sealFailed }
        return combined
    }

    public static func open(_ combined: Data, using key: SymmetricKey) throws -> Data {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: combined), using: key)
    }

    /// Convenience with a raw key (`Data`, 16/24/32 bytes).
    public static func seal(_ data: Data, keyData: Data) throws -> Data { try seal(data, using: SymmetricKey(data: keyData)) }
    public static func open(_ combined: Data, keyData: Data) throws -> Data { try open(combined, using: SymmetricKey(data: keyData)) }

    /// Seal with **Additional Authenticated Data** (bound to the ciphertext but
    /// not encrypted — e.g. a header/version). Opening requires the same `aad`.
    public static func seal(_ data: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data {
        guard let combined = try AES.GCM.seal(data, using: key, authenticating: aad).combined else { throw CipherError.sealFailed }
        return combined
    }
    public static func open(_ combined: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: combined), using: key, authenticating: aad)
    }
}

/// Timing-safe comparison — use for secrets/MACs to avoid timing side-channels.
public enum ConstantTime {
    public static func equal(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in 0..<lhs.count { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }
}

/// Hashing + HMAC.
public enum Hashing {
    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    public static func sha512(_ data: Data) -> Data { Data(SHA512.hash(data: data)) }
    public static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    public static func sha256Hex(_ data: Data) -> String { hex(sha256(data)) }
    public static func hmacSHA256(_ data: Data, key: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
}

public extension String {
    /// Hex-encoded SHA-256 of this string's UTF-8 bytes.
    var sha256Hex: String { Hashing.sha256Hex(Data(utf8)) }
}

/// Cryptographically-secure random helpers.
public enum CryptoRandom {
    public static func bytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let ok = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return ok == errSecSuccess ? data : Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }

    private static let alphanumerics = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    public static func string(length: Int, alphabet: [Character]? = nil) -> String {
        let chars = alphabet ?? alphanumerics
        guard !chars.isEmpty else { return "" }
        return String((0..<length).map { _ in chars[Int.random(in: 0..<chars.count)] })
    }
}

/// RSA public-key encryption (Security framework).
public enum RSA {
    /// Encrypt with an RSA public key in DER form, using PKCS#1 padding.
    public static func encrypt(_ data: Data, publicKeyDER: Data,
                               algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) throws -> Data {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(publicKeyDER as CFData, attributes as CFDictionary, &error) else {
            throw CipherError.invalidKey
        }
        guard let cipher = SecKeyCreateEncryptedData(key, algorithm, data as CFData, &error) else {
            throw CipherError.rsaFailed
        }
        return cipher as Data
    }
}

/// Thread-safe in-memory key store (e.g. per-session AES keys).
public actor AESKeyManager {
    public static let shared = AESKeyManager()
    private var keys: [String: SymmetricKey] = [:]
    public init() {}

    /// Existing key for `id`, or a freshly generated one (stored).
    public func key(for id: String) -> SymmetricKey {
        if let key = keys[id] { return key }
        let key = AESGCM.randomKey()
        keys[id] = key
        return key
    }
    public func set(_ key: SymmetricKey, for id: String) { keys[id] = key }
    public func remove(_ id: String) { keys[id] = nil }
    public func removeAll() { keys.removeAll() }
}
