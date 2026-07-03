//
//  RSAPrivate.swift
//  CipherServer
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import Security

/// RSA operations that use a **private key** — decrypt data encrypted to you,
/// or sign data others verify. (Public-key encrypt lives in `CipherKit.RSA`.)
public enum RSAPrivate {
    public enum Failure: Error { case invalidKey, decryptFailed, signFailed }

    /// Build a private `SecKey` from a DER (PKCS#1) representation.
    public static func privateKey(der: Data) throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            throw Failure.invalidKey
        }
        return key
    }

    public static func decrypt(_ cipher: Data, privateKey: SecKey,
                               algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(privateKey, algorithm, cipher as CFData, &error) else {
            throw Failure.decryptFailed
        }
        return plain as Data
    }

    public static func sign(_ data: Data, privateKey: SecKey,
                            algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
            throw Failure.signFailed
        }
        return signature as Data
    }

    public static func verify(_ signature: Data, of data: Data, publicKey: SecKey,
                              algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) -> Bool {
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(publicKey, algorithm, data as CFData, signature as CFData, &error)
    }
}
