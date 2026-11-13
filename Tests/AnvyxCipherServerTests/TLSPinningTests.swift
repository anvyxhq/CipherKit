import XCTest
import Security
import AnvyxCipherKit
@testable import AnvyxCipherServer

final class TLSPinningTests: XCTestCase {

    private let otherPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    // MARK: - SPKI pin

    func testPinMatchesOpenSSLForEveryKeyType() throws {
        for fixture in PinFixture.all {
            let certificate = try XCTUnwrap(fixture.certificate, fixture.name)
            XCTAssertEqual(SPKIPin.pin(for: certificate), fixture.pin, fixture.name)
            XCTAssertEqual(PinnedSessionDelegate.pin(for: certificate), fixture.pin, fixture.name)
        }
    }

    func testPinIsNotTheBareKeyHash() throws {
        let certificate = try XCTUnwrap(PinFixture.rsa2048.certificate)
        let key = try XCTUnwrap(SecCertificateCopyKey(certificate))
        let bare = try XCTUnwrap(SecKeyCopyExternalRepresentation(key, nil) as Data?)
        XCTAssertNotEqual(Hashing.sha256(bare).base64EncodedString(), PinFixture.rsa2048.pin)
    }

    func testDERLengthEncoding() {
        XCTAssertEqual(DER.length(0), Data([0x00]))
        XCTAssertEqual(DER.length(127), Data([0x7f]))
        XCTAssertEqual(DER.length(128), Data([0x81, 0x80]))
        XCTAssertEqual(DER.length(255), Data([0x81, 0xff]))
        XCTAssertEqual(DER.length(256), Data([0x82, 0x01, 0x00]))
        XCTAssertEqual(DER.length(65_536), Data([0x83, 0x01, 0x00, 0x00]))
    }

    // MARK: - Policy

    func testHostMatchingIsExactOrSubdomain() {
        let policy = PinPolicy(hosts: ["Example.com.", "*.api.test"], pins: ["a", "b"])
        XCTAssertTrue(policy.covers(host: "example.com"))
        XCTAssertTrue(policy.covers(host: "API.Example.com"))
        XCTAssertTrue(policy.covers(host: "a.b.example.com."))
        XCTAssertTrue(policy.covers(host: "v1.api.test"))
        XCTAssertFalse(policy.covers(host: "badexample.com"))
        XCTAssertFalse(policy.covers(host: "example.com.evil.net"))
        XCTAssertFalse(policy.covers(host: "com"))
        XCTAssertFalse(policy.covers(host: ""))
    }

    func testEmptyOrHalfFilledPolicyIsOff() {
        XCTAssertFalse(PinPolicy(hosts: [], pins: []).isEnabled)
        XCTAssertFalse(PinPolicy(hosts: ["example.com"], pins: []).isEnabled)
        XCTAssertFalse(PinPolicy(hosts: [], pins: ["a", "b"]).isEnabled)
        XCTAssertFalse(PinPolicy(hosts: [" "], pins: ["", " "]).isEnabled)
        XCTAssertFalse(PinPolicy(hosts: ["example.com"], pins: []).covers(host: "example.com"))
        XCTAssertTrue(PinPolicy(hosts: ["example.com"], pins: ["a", "b"]).isEnabled)
    }

    func testChainMatching() throws {
        let leaf = try XCTUnwrap(PinFixture.p256.certificate)
        let issuer = try XCTUnwrap(PinFixture.rsa2048.certificate)
        let chain = [leaf, issuer]

        let anyInChain = PinPolicy(hosts: ["h"], pins: [PinFixture.rsa2048.pin, otherPin])
        XCTAssertTrue(anyInChain.matches(chain: chain))

        let leafOnly = PinPolicy(hosts: ["h"], pins: [PinFixture.rsa2048.pin, otherPin], matchAnyInChain: false)
        XCTAssertFalse(leafOnly.matches(chain: chain))
        XCTAssertTrue(leafOnly.matches(chain: [issuer, leaf]))

        // Backup pin: either of the two keys is enough.
        let backup = PinPolicy(hosts: ["h"], pins: [otherPin, PinFixture.p256.pin], matchAnyInChain: false)
        XCTAssertTrue(backup.matches(chain: chain))

        XCTAssertFalse(anyInChain.matches(chain: []))
        XCTAssertFalse(PinPolicy(hosts: ["h"], pins: [otherPin, "x"]).matches(chain: chain))
    }

    // MARK: - Delegate

    /// A trust object that passes system evaluation by anchoring the fixture itself.
    private func trust(for fixture: PinFixture, anchored: Bool = true) throws -> SecTrust {
        let certificate = try XCTUnwrap(fixture.certificate)
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust), errSecSuccess)
        let result = try XCTUnwrap(trust)
        if anchored {
            XCTAssertEqual(SecTrustSetAnchorCertificates(result, [certificate] as CFArray), errSecSuccess)
        }
        return result
    }

    func testUncoveredHostGetsDefaultHandling() throws {
        let delegate = PinnedSessionDelegate(policy: PinPolicy(hosts: ["example.com"], pins: [otherPin, "x"]))
        XCTAssertEqual(delegate.disposition(host: "other.org", trust: try trust(for: .p256)), .performDefaultHandling)

        let off = PinnedSessionDelegate(policy: PinPolicy(hosts: ["example.com"], pins: []))
        XCTAssertEqual(off.disposition(host: "example.com", trust: try trust(for: .p256)), .performDefaultHandling)
    }

    func testCoveredHostNeedsTrustAndPin() throws {
        let good = PinnedSessionDelegate(policy: PinPolicy(hosts: ["example.com"],
                                                            pins: [PinFixture.p256.pin, otherPin]))
        XCTAssertEqual(good.disposition(host: "api.example.com", trust: try trust(for: .p256)), .useCredential)
        // Pin matches but the chain is not trusted by the system.
        XCTAssertEqual(good.disposition(host: "api.example.com", trust: try trust(for: .p256, anchored: false)),
                       .cancelAuthenticationChallenge)
        // Trusted chain, wrong key.
        XCTAssertEqual(good.disposition(host: "api.example.com", trust: try trust(for: .rsa2048)),
                       .cancelAuthenticationChallenge)
    }

    func testHostlessInitializerPinsEveryHost() throws {
        let spki = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: [PinFixture.rsa2048.pin])
        XCTAssertEqual(spki.disposition(host: "anything.test", trust: try trust(for: .rsa2048)), .useCredential)
        XCTAssertEqual(spki.disposition(host: "anything.test", trust: try trust(for: .p256)),
                       .cancelAuthenticationChallenge)

        // Bare-key hashes from earlier versions keep working.
        let certificate = try XCTUnwrap(PinFixture.rsa2048.certificate)
        let key = try XCTUnwrap(SecCertificateCopyKey(certificate))
        let bare = try XCTUnwrap(SecKeyCopyExternalRepresentation(key, nil) as Data?)
        let legacy = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: [Hashing.sha256(bare).base64EncodedString()])
        XCTAssertEqual(legacy.disposition(host: "anything.test", trust: try trust(for: .rsa2048)), .useCredential)

        let none = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: [])
        XCTAssertEqual(none.disposition(host: "anything.test", trust: try trust(for: .rsa2048)),
                       .cancelAuthenticationChallenge)
    }
}
