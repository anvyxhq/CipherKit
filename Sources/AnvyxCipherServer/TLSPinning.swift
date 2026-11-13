//
//  TLSPinning.swift
//  CipherServer
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import Security
import AnvyxCipherKit

/// Computes the standard public-key pin of a certificate:
/// `base64(SHA-256(SubjectPublicKeyInfo))`.
///
/// The value equals what the usual command line prints:
///
/// ```sh
/// openssl x509 -in cert.pem -pubkey -noout \
///   | openssl pkey -pubin -outform der \
///   | openssl dgst -sha256 -binary | base64
/// ```
///
/// `SecKeyCopyExternalRepresentation` returns the *bare* key (PKCS#1 for RSA,
/// the X9.63 point for EC), so the `SubjectPublicKeyInfo` wrapper is rebuilt
/// here before hashing. Supported keys: RSA of any size and EC P-256 / P-384 /
/// P-521.
public enum SPKIPin {

    /// The pin of `certificate`, or `nil` when the key type is not supported.
    public static func pin(for certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate) else { return nil }
        return pin(for: key)
    }

    /// The pin of a public key, or `nil` when the key type is not supported.
    public static func pin(for publicKey: SecKey) -> String? {
        subjectPublicKeyInfo(for: publicKey).map { Hashing.sha256($0).base64EncodedString() }
    }

    /// DER-encoded `SubjectPublicKeyInfo` of a public key, or `nil` when the
    /// key type is not supported.
    ///
    ///     SubjectPublicKeyInfo ::= SEQUENCE {
    ///         algorithm         AlgorithmIdentifier,
    ///         subjectPublicKey  BIT STRING }
    public static func subjectPublicKeyInfo(for publicKey: SecKey) -> Data? {
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let type = attributes[kSecAttrKeyType] as? String,
              let bits = attributes[kSecAttrKeySizeInBits] as? Int,
              let algorithm = algorithmIdentifier(keyType: type, bits: bits) else { return nil }
        return DER.sequence(algorithm + DER.bitString(raw))
    }

    // MARK: - AlgorithmIdentifier

    /// RSA has a single identifier whatever the modulus size; EC carries the
    /// curve OID, so the size selects the curve.
    private static func algorithmIdentifier(keyType: String, bits: Int) -> Data? {
        if keyType == kSecAttrKeyTypeRSA as String {
            return DER.sequence(Data(OID.rsaEncryption) + Data([0x05, 0x00]))   // NULL parameters
        }
        if keyType == kSecAttrKeyTypeECSECPrimeRandom as String {
            let curve: [UInt8]
            switch bits {
            case 256: curve = OID.prime256v1
            case 384: curve = OID.secp384r1
            case 521: curve = OID.secp521r1
            default: return nil
            }
            return DER.sequence(Data(OID.ecPublicKey) + Data(curve))
        }
        return nil
    }

    /// Object identifiers, already wrapped with tag and length.
    private enum OID {
        static let rsaEncryption: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        static let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
        static let prime256v1: [UInt8] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        static let secp384r1: [UInt8] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
        static let secp521r1: [UInt8] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]
    }
}

/// Minimal DER writer — just what `SubjectPublicKeyInfo` needs.
enum DER {
    /// Definite length: one byte below 128, otherwise `0x80 | byteCount`
    /// followed by the big-endian length.
    static func length(_ count: Int) -> Data {
        guard count >= 0x80 else { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }

    static func sequence(_ body: Data) -> Data {
        Data([0x30]) + length(body.count) + body
    }

    /// A BIT STRING starts with the count of unused bits; keys are whole bytes, so 0.
    static func bitString(_ body: Data) -> Data {
        Data([0x03]) + length(body.count + 1) + Data([0x00]) + body
    }
}

/// Which hosts are pinned, and to which public keys.
///
/// ```swift
/// let policy = PinPolicy(hosts: ["api.example.com"],
///                        pins: ["<current pin>", "<backup pin>"])
/// ```
///
/// - A host is covered when it equals an entry or is a subdomain of it
///   (`example.com` covers `api.example.com`, not `badexample.com`).
/// - Pins are ``SPKIPin`` values (`base64(SHA-256(SubjectPublicKeyInfo))`).
/// - A policy with no hosts **or** no pins is disabled: nothing is pinned and
///   every connection gets the system's default handling.
///
/// ## Rotation
///
/// Always ship at least two pins: the key in use and a backup key that is
/// kept offline (debug builds assert this). To rotate, release a build that
/// **adds** the new pin first, wait until that build is widely installed, switch
/// the server key, and only then remove the old pin in a later build. Removing
/// the old pin before the new one is deployed locks existing installs out.
public struct PinPolicy: Sendable, Equatable {
    /// Lower-cased host names the policy applies to.
    public let hosts: Set<String>
    /// Accepted pins.
    public let pins: Set<String>
    /// `true` accepts a match on any certificate of the validated chain (leaf,
    /// intermediate or root); `false` checks the leaf only.
    public let matchAnyInChain: Bool

    public init(hosts: Set<String>, pins: Set<String>, matchAnyInChain: Bool = true) {
        self.hosts = Set(hosts.map(Self.normalize).filter { !$0.isEmpty })
        self.pins = Set(pins.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })
        self.matchAnyInChain = matchAnyInChain
        assert(!isEnabled || self.pins.count >= 2,
               "PinPolicy needs at least 2 pins (current + backup) so the key can be rotated.")
    }

    /// `false` when hosts or pins are missing — pinning is then off.
    public var isEnabled: Bool { !hosts.isEmpty && !pins.isEmpty }

    /// Whether `host` is one of ``hosts`` or a subdomain of one. Always `false`
    /// for a disabled policy.
    public func covers(host: String) -> Bool {
        guard isEnabled else { return false }
        let host = Self.normalize(host)
        guard !host.isEmpty else { return false }
        return hosts.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    /// Whether the chain (leaf first) carries a pinned key. Certificates whose
    /// key type is unsupported never match.
    public func matches(chain: [SecCertificate]) -> Bool {
        let candidates = matchAnyInChain ? chain[...] : chain.prefix(1)
        return candidates.contains { certificate in
            SPKIPin.pin(for: certificate).map(pins.contains) ?? false
        }
    }

    private static func normalize(_ host: String) -> String {
        var host = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasPrefix("*.") { host.removeFirst(2) }
        while host.hasSuffix(".") { host.removeLast() }
        return host
    }
}

/// A `URLSessionDelegate` that pins server public keys according to a
/// ``PinPolicy``.
///
/// For a host the policy covers, the connection succeeds only if the system
/// trust evaluation passes **and** a certificate of the chain carries a pinned
/// key. Hosts outside the policy — and every host when the policy is
/// disabled — get the system's default handling.
///
/// ```swift
/// let policy = PinPolicy(hosts: ["api.example.com"], pins: ["<current>", "<backup>"])
/// let delegate = PinnedSessionDelegate(policy: policy)
/// let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
/// ```
public final class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    /// The policy in effect.
    public let policy: PinPolicy
    /// Set by the host-less initializer: every host is pinned, leaf only.
    private let legacyPins: Set<String>?

    public init(policy: PinPolicy) {
        self.policy = policy
        self.legacyPins = nil
    }

    /// Pins the **leaf** key of every host the session talks to.
    ///
    /// Prefer ``init(policy:)``, which scopes pinning to named hosts and can
    /// match intermediates. Pins are ``SPKIPin`` values; hashes of the bare key
    /// (what earlier versions of ``pin(for:)`` returned) are still accepted
    /// here so existing configurations keep working.
    public init(pinnedPublicKeyHashesBase64 pins: Set<String>) {
        self.policy = PinPolicy(hosts: [], pins: pins, matchAnyInChain: false)
        self.legacyPins = pins
    }

    /// The pin of a certificate — `base64(SHA-256(SubjectPublicKeyInfo))`, the
    /// same value the standard `openssl` pipeline prints. See ``SPKIPin``.
    public static func pin(for certificate: SecCertificate) -> String? {
        SPKIPin.pin(for: certificate)
    }

    public func urlSession(_ session: URLSession,
                           didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        let disposition = disposition(host: challenge.protectionSpace.host, trust: trust)
        completionHandler(disposition, disposition == .useCredential ? URLCredential(trust: trust) : nil)
    }

    /// The decision for one server-trust challenge.
    func disposition(host: String, trust: SecTrust) -> URLSession.AuthChallengeDisposition {
        guard legacyPins != nil || policy.covers(host: host) else { return .performDefaultHandling }
        // Standard chain validation first; the pin is an extra condition, never a replacement.
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error),
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], !chain.isEmpty else {
            return .cancelAuthenticationChallenge
        }
        if let legacyPins {
            return Self.legacyMatch(leaf: chain[0], pins: legacyPins) ? .useCredential : .cancelAuthenticationChallenge
        }
        return policy.matches(chain: chain) ? .useCredential : .cancelAuthenticationChallenge
    }

    private static func legacyMatch(leaf: SecCertificate, pins: Set<String>) -> Bool {
        if let pin = SPKIPin.pin(for: leaf), pins.contains(pin) { return true }
        guard let key = SecCertificateCopyKey(leaf),
              let bare = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return false }
        return pins.contains(Hashing.sha256(bare).base64EncodedString())
    }
}
