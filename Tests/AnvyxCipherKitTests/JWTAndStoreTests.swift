//
//  JWTAndStoreTests.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import AnvyxCipherKit

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
            payload: ["iss": "https://appleid.apple.com", "aud": "com.anvyx.app", "nonce": "abc", "exp": exp]
        ) { try! key.signature(for: $0).rawRepresentation }

        guard let jwt = JWT(token) else { return XCTFail("parse") }
        XCTAssertEqual(jwt.algorithm, "ES256")
        XCTAssertTrue(JWTVerifier.verifyES256(jwt, publicKey: key.publicKey))
        XCTAssertTrue(JWTVerifier.validateClaims(jwt, issuer: "https://appleid.apple.com",
                                                 audience: "com.anvyx.app", nonce: "abc"))
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
        let store = KeychainStore(service: "com.anvyx.cipherkit.tests")
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
        // Overwrite keeps a single item and replaces the value.
        try store.set(Data("second".utf8), for: "k", accessibility: .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(try store.requireData(for: "k"), Data("second".utf8))
        store.remove(for: "k")
        XCTAssertNil(store.data(for: "k"))
        XCTAssertThrowsError(try store.requireData(for: "k")) {
            XCTAssertEqual($0 as? KeychainStore.Failure, .itemNotFound)
        }
    }

    func testKeychainFailureMapping() {
        XCTAssertEqual(KeychainStore.Failure(errSecItemNotFound), .itemNotFound)
        XCTAssertEqual(KeychainStore.Failure(errSecInteractionNotAllowed), .interactionNotAllowed)
        XCTAssertEqual(KeychainStore.Failure(errSecDuplicateItem), .status(errSecDuplicateItem))
        XCTAssertNotEqual(KeychainStore.Failure(errSecInteractionNotAllowed), .itemNotFound)
    }

    func testKeychainQueryBuilding() {
        let store = KeychainStore(service: "svc", accessibility: .whenUnlockedThisDeviceOnly)
        let item = store.itemQuery(account: "acct")
        XCTAssertEqual(item[kSecAttrService] as? String, "svc")
        XCTAssertEqual(item[kSecAttrAccount] as? String, "acct")
        XCTAssertEqual(item[kSecClass] as? String, kSecClassGenericPassword as String)
        // The match query must not carry value/accessibility, or SecItemUpdate would miss the item.
        XCTAssertNil(item[kSecValueData])
        XCTAssertNil(item[kSecAttrAccessible])

        let read = store.readQuery(account: "acct")
        XCTAssertEqual(read[kSecReturnData] as? Bool, true)
        XCTAssertEqual(read[kSecMatchLimit] as? String, kSecMatchLimitOne as String)

        let payload = Data([1, 2, 3])
        let defaults = store.valueAttributes(payload, accessibility: nil)
        XCTAssertEqual(defaults[kSecValueData] as? Data, payload)
        XCTAssertEqual(defaults[kSecAttrAccessible] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        let overridden = store.valueAttributes(payload, accessibility: .afterFirstUnlock)
        XCTAssertEqual(overridden[kSecAttrAccessible] as? String, kSecAttrAccessibleAfterFirstUnlock as String)
        XCTAssertEqual(KeychainStore(service: "svc").valueAttributes(payload, accessibility: nil)[kSecAttrAccessible] as? String,
                       kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    func testSecureZero() {
        var data = Data([1, 2, 3, 4, 5])
        data.secureZero()
        XCTAssertTrue(data.allSatisfy { $0 == 0 })
    }
}
