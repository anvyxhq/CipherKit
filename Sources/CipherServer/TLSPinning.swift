//
//  TLSPinning.swift
//  CipherServer
//
//  Created by AnhPT on 03/07/2026.
//

import Foundation
import Security
import CipherKit

/// A `URLSessionDelegate` that pins the server's leaf **public key** — the
/// connection only succeeds if its key's SHA-256 (base64) is in the pinned set.
///
/// ```swift
/// let delegate = PinnedSessionDelegate(pinnedPublicKeyHashesBase64: ["…"])
/// let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
/// ```
public final class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    private let pins: Set<String>

    public init(pinnedPublicKeyHashesBase64 pins: Set<String>) {
        self.pins = pins
    }

    /// Compute the pin (base64 SHA-256 of the leaf public key) for a certificate —
    /// use once to obtain the value you hard-code in `pins`.
    public static func pin(for certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate),
              let der = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        return Hashing.sha256(der).base64EncodedString()
    }

    public func urlSession(_ session: URLSession,
                           didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        // Standard chain validation first.
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        // Then pin the leaf public key.
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first, let hash = Self.pin(for: leaf) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        if pins.contains(hash) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
