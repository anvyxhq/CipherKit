//
//  AESKeyManagerTests.swift
//  CipherKit
//
//  Created by AnhPT on 13/07/2026.
//

import XCTest
import CryptoKit
@testable import AnvyxCipherKit

final class AESKeyManagerTests: XCTestCase {

    func testKeyForIsStableAndDistinctPerID() async {
        let manager = AESKeyManager()
        let a1 = await manager.key(for: "session-a")
        let a2 = await manager.key(for: "session-a")
        let b = await manager.key(for: "session-b")

        XCTAssertEqual(a1, a2, "same id returns the same stored key")
        XCTAssertNotEqual(a1, b, "different ids get different keys")
    }

    func testSetOverridesStoredKey() async {
        let manager = AESKeyManager()
        _ = await manager.key(for: "id")
        let injected = AESGCM.randomKey()
        await manager.set(injected, for: "id")
        let fetched = await manager.key(for: "id")
        XCTAssertEqual(fetched, injected)
    }

    func testRemoveDropsKeySoNextIsRegenerated() async {
        let manager = AESKeyManager()
        let original = await manager.key(for: "id")
        await manager.remove("id")
        let regenerated = await manager.key(for: "id")
        XCTAssertNotEqual(original, regenerated, "removed key is replaced by a fresh one")
    }

    func testRemoveAllClearsEverything() async {
        let manager = AESKeyManager()
        let first = await manager.key(for: "x")
        await manager.removeAll()
        let afterClear = await manager.key(for: "x")
        XCTAssertNotEqual(first, afterClear)
    }
}
