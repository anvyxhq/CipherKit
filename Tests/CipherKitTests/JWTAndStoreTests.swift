//
//  JWTAndStoreTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import CipherKit

final class JWTAndStoreTests: XCTestCase {

    private func makeToken(header: [String: Any], payload: [String: Any],
                           sign: (Data) -> Data) -> String {
        let h = try! JSONSerialization.data(withJSONObject: header)
        let p = try! JSONSerialization.data(withJSONObject: payload)
        let input = "\(h.base64URLEncodedString).\(p.base64URLEncodedString)"
        return "\(input).\(sign(Data(input.utf8)).base64URLEncodedString)"
    }

    func testJWTES256VerifyAndClaims() throws {
        let key = P256.Signing.PrivateKey()
        let exp = Date().addingTimeInterval(3600).timeIntervalSince1970
        let token = makeToken(
            header: ["alg": "ES256", "typ": "JWT"],
            payload: ["iss": "https://appleid.apple.com", "aud": "com.anvora.app", "nonce": "abc", "exp": exp]
        ) { try! key.signature(for: $0).rawRepresentation }

        guard let jwt = JWT(token) else { return XCTFail("parse") }
        XCTAssertEqual(jwt.algorithm, "ES256")
        XCTAssertTrue(JWTVerifier.verifyES256(jwt, publicKey: key.publicKey))
        XCTAssertTrue(JWTVerifier.validateClaims(jwt, issuer: "https://appleid.apple.com",
                                                 audience: "com.anvora.app", nonce: "abc"))
        XCTAssertFalse(JWTVerifier.validateClaims(jwt, nonce: "wrong"))
    }

    func testJWTES256RejectsTamperAndExpiry() throws {
        let key = P256.Signing.PrivateKey()
        let expired = Date().addingTimeInterval(-10).timeIntervalSince1970
        let token = makeToken(header: ["alg": "ES256"], payload: ["exp": expired]) {
            try! key.signature(for: $0).rawRepresentation
        }
        guard let jwt = JWT(token) else { return XCTFail() }
        XCTAssertTrue(JWTVerifier.verifyES256(jwt, publicKey: key.publicKey))   // signature valid
        XCTAssertFalse(JWTVerifier.validateClaims(jwt))                          // but expired
        XCTAssertFalse(JWTVerifier.verifyES256(jwt, publicKey: P256.Signing.PrivateKey().publicKey)) // wrong key
    }

    func testJWTRS256Verify() throws {
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
              let pub = SecKeyCopyPublicKey(priv),
              let pubDER = SecKeyCopyExternalRepresentation(pub, &error) as Data? else { return XCTFail("keygen") }
        let token = makeToken(header: ["alg": "RS256"], payload: ["iss": "x"]) { data in
            SecKeyCreateSignature(priv, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, &error)! as Data
        }
        guard let jwt = JWT(token) else { return XCTFail() }
        XCTAssertTrue(JWTVerifier.verifyRS256(jwt, publicKeyDER: pubDER))
    }

    func testKeychainStoreRoundTrip() throws {
        let store = KeychainStore(service: "com.anvora.cipherkit.tests")
        let key = AESGCM.randomKey()
        store.remove(for: "k")
        do {
            try store.setKey(key, for: "k")
        } catch KeychainStore.Failure.status(-34018) {
            // Keychain needs an app host / entitlement; unavailable in SPM test bundle.
            throw XCTSkip("Keychain unavailable in this test host (errSecMissingEntitlement)")
        }
        XCTAssertEqual(store.key(for: "k")?.withUnsafeBytes { Data($0) },
                       key.withUnsafeBytes { Data($0) })
        store.remove(for: "k")
        XCTAssertNil(store.data(for: "k"))
    }

    func testSecureZero() {
        var data = Data([1, 2, 3, 4, 5])
        data.secureZero()
        XCTAssertTrue(data.allSatisfy { $0 == 0 })
    }
}
