//
//  JWTSigner.swift
//  CipherServer
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import CryptoKit
import Security
import CipherKit

/// Create signed JWTs (verify them with `CipherKit.JWTVerifier`).
public enum JWTSigner {

    public enum Algorithm {
        case hs256(secret: Data)
        case es256(privateKey: P256.Signing.PrivateKey)
        case rs256(privateKey: SecKey)

        var name: String {
            switch self { case .hs256: "HS256"; case .es256: "ES256"; case .rs256: "RS256" }
        }
    }

    public enum Failure: Error { case serializationFailed, signingFailed }

    public static func sign(claims: [String: Any],
                            algorithm: Algorithm,
                            extraHeaders: [String: Any] = [:]) throws -> String {
        var header: [String: Any] = ["typ": "JWT", "alg": algorithm.name]
        header.merge(extraHeaders) { _, new in new }

        guard let headerData = try? JSONSerialization.data(withJSONObject: header),
              let claimsData = try? JSONSerialization.data(withJSONObject: claims) else {
            throw Failure.serializationFailed
        }
        let signingInput = "\(headerData.base64URLEncodedString).\(claimsData.base64URLEncodedString)"
        let signature = try sign(Data(signingInput.utf8), with: algorithm)
        return "\(signingInput).\(signature.base64URLEncodedString)"
    }

    private static func sign(_ data: Data, with algorithm: Algorithm) throws -> Data {
        switch algorithm {
        case let .hs256(secret):
            return Hashing.hmacSHA256(data, key: secret)
        case let .es256(privateKey):
            return try privateKey.signature(for: data).rawRepresentation   // JWT uses raw R‖S
        case let .rs256(privateKey):
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256,
                                                        data as CFData, &error) else {
                throw Failure.signingFailed
            }
            return signature as Data
        }
    }
}
