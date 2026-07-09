//
//  JWT.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  Offline JWT parsing + signature/claim verification (e.g. Sign in with Apple
//  identity tokens: RS256 with Apple's public key).

import Foundation
import CryptoKit
import Security

/// A parsed JSON Web Token.
public struct JWT {
    public let header: [String: Any]
    public let payload: [String: Any]
    public let signature: Data
    /// The "header.payload" bytes that were signed.
    public let signingInput: String

    public init?(_ token: String) {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Data(base64URLEncoded: String(parts[0])),
              let payloadData = Data(base64URLEncoded: String(parts[1])),
              let signature = Data(base64URLEncoded: String(parts[2])),
              let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
              let payload = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any]
        else { return nil }
        self.header = header
        self.payload = payload
        self.signature = signature
        self.signingInput = "\(parts[0]).\(parts[1])"
    }

    public var algorithm: String? { header["alg"] as? String }
    public var keyID: String? { header["kid"] as? String }
    public func claim<T>(_ key: String, as: T.Type = T.self) -> T? { payload[key] as? T }
    public var expiration: Date? { (payload["exp"] as? Double).map { Date(timeIntervalSince1970: $0) } }
}

public enum JWTVerifier {

    /// Verify an ES256 (P-256 ECDSA) signature. JWT signatures are raw R‖S (64 bytes).
    public static func verifyES256(_ jwt: JWT, publicKey: P256.Signing.PublicKey) -> Bool {
        guard jwt.signature.count == 64,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: jwt.signature) else { return false }
        return publicKey.isValidSignature(signature, for: Data(jwt.signingInput.utf8))
    }

    /// Verify an HS256 (HMAC-SHA256) signature with the shared secret.
    public static func verifyHS256(_ jwt: JWT, secret: Data) -> Bool {
        let expected = Hashing.hmacSHA256(Data(jwt.signingInput.utf8), key: secret)
        return ConstantTime.equal(expected, jwt.signature)
    }

    /// Verify an RS256 (RSA PKCS#1 v1.5 + SHA-256) signature with a DER public key
    /// (used by Sign in with Apple).
    public static func verifyRS256(_ jwt: JWT, publicKeyDER: Data) -> Bool {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(publicKeyDER as CFData, attributes as CFDictionary, &error) else { return false }
        return SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                     Data(jwt.signingInput.utf8) as CFData, jwt.signature as CFData, &error)
    }

    /// Validate standard claims (expiry, issuer, audience, nonce). `audience`
    /// matches either a string `aud` or membership in an `aud` array.
    public static func validateClaims(_ jwt: JWT, issuer: String? = nil, audience: String? = nil,
                                      nonce: String? = nil, now: Date = Date()) -> Bool {
        if let exp = jwt.expiration, now >= exp { return false }
        if let issuer, jwt.claim("iss", as: String.self) != issuer { return false }
        if let audience {
            if let single = jwt.claim("aud", as: String.self) {
                if single != audience { return false }
            } else if let list = jwt.claim("aud", as: [String].self) {
                if !list.contains(audience) { return false }
            } else { return false }
        }
        if let nonce, jwt.claim("nonce", as: String.self) != nonce { return false }
        return true
    }
}
