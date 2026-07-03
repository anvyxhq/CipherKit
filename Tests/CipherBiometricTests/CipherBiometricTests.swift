//
//  CipherBiometricTests.swift
//  CipherBiometric
//
//  Created by AnhPT on 03/07/2026.
//

import XCTest
import CryptoKit
@testable import CipherBiometric

final class CipherBiometricTests: XCTestCase {
    // Secure Enclave + biometrics require a real device; here we verify the API
    // is callable and the availability check works on the Simulator.
    func testAvailabilityCallable() {
        _ = BiometricKey.isAvailable()
    }

    func testVaultRemoveIsSafe() {
        // No biometric needed to delete; verifies the API links/compiles.
        BiometricVault.remove(account: "cipherkit.tests.nonexistent")
    }
}
