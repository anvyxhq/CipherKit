//
//  CipherServerTests.swift
//  CipherServer
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
import CipherKit
@testable import CipherServer

final class CipherServerTests: XCTestCase {

    func testJWTSignHS256VerifiesWithCore() throws {
        let secret = Data("supersecret".utf8)
        let token = try JWTSigner.sign(claims: ["sub": "42", "role": "admin"], algorithm: .hs256(secret: secret))
        guard let jwt = JWT(token) else { return XCTFail("parse") }
        XCTAssertEqual(jwt.algorithm, "HS256")
        XCTAssertTrue(JWTVerifier.verifyHS256(jwt, secret: secret))
        XCTAssertFalse(JWTVerifier.verifyHS256(jwt, secret: Data("wrong".utf8)))
        XCTAssertEqual(jwt.claim("role", as: String.self), "admin")
    }

    func testJWTSignES256VerifiesWithCore() throws {
        let key = P256.Signing.PrivateKey()
        let token = try JWTSigner.sign(claims: ["sub": "1"], algorithm: .es256(privateKey: key))
        guard let jwt = JWT(token) else { return XCTFail() }
        XCTAssertTrue(JWTVerifier.verifyES256(jwt, publicKey: key.publicKey))
    }

    func testRSASignVerifyAndDecryptRoundTrip() throws {
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
              let pub = SecKeyCopyPublicKey(priv) else { return XCTFail("keygen") }

        // sign / verify
        let message = Data("payload".utf8)
        let signature = try RSAPrivate.sign(message, privateKey: priv)
        XCTAssertTrue(RSAPrivate.verify(signature, of: message, publicKey: pub))

        // public encrypt (core) → private decrypt (server)
        guard let pubDER = SecKeyCopyExternalRepresentation(pub, &error) as Data? else { return XCTFail() }
        let cipher = try RSA.encrypt(message, publicKeyDER: pubDER)
        XCTAssertEqual(try RSAPrivate.decrypt(cipher, privateKey: priv), message)

        // JWT RS256 sign → verify
        let token = try JWTSigner.sign(claims: ["iss": "me"], algorithm: .rs256(privateKey: priv))
        guard let jwt = JWT(token), let der = SecKeyCopyExternalRepresentation(pub, &error) as Data? else { return XCTFail() }
        XCTAssertTrue(JWTVerifier.verifyRS256(jwt, publicKeyDER: der))
    }

    func testPinnedDelegateConstructs() {
        _ = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: ["abc123="])
    }
}
