//
//  OTPAuthURI.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  Parse / build `otpauth://` URIs (the content of 2FA QR codes).

import Foundation

public struct OTPAuthURI: Equatable {
    public enum Kind: String { case totp, hotp }

    public var kind: Kind
    public var label: String
    public var issuer: String?
    public var secret: Data
    public var digits: Int
    public var algorithm: OTPAlgorithm
    public var period: TimeInterval   // TOTP
    public var counter: UInt64        // HOTP

    public init(kind: Kind, label: String, issuer: String? = nil, secret: Data,
                digits: Int = 6, algorithm: OTPAlgorithm = .sha1,
                period: TimeInterval = 30, counter: UInt64 = 0) {
        self.kind = kind; self.label = label; self.issuer = issuer; self.secret = secret
        self.digits = digits; self.algorithm = algorithm; self.period = period; self.counter = counter
    }

    /// Parse an `otpauth://totp/Issuer:acc?secret=BASE32&issuer=…&digits=…&period=…&algorithm=SHA1`.
    public init?(_ uriString: String) {
        guard let components = URLComponents(string: uriString),
              components.scheme?.lowercased() == "otpauth",
              let host = components.host, let kind = Kind(rawValue: host.lowercased()) else { return nil }

        let items = components.queryItems ?? []
        func value(_ name: String) -> String? { items.first { $0.name == name }?.value }
        guard let base32 = value("secret"), let secret = Base32.decode(base32), !secret.isEmpty else { return nil }

        self.kind = kind
        self.label = components.path.hasPrefix("/") ? String(components.path.dropFirst()) : components.path
        self.issuer = value("issuer") ?? (label.contains(":") ? label.split(separator: ":").first.map(String.init) : nil)
        self.secret = secret
        self.digits = value("digits").flatMap(Int.init) ?? 6
        self.algorithm = value("algorithm").flatMap(OTPAlgorithm.init(name:)) ?? .sha1
        self.period = value("period").flatMap(TimeInterval.init) ?? 30
        self.counter = value("counter").flatMap(UInt64.init) ?? 0
    }

    /// Serialize back to an `otpauth://` URI.
    public var uriString: String {
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = kind.rawValue
        components.path = "/" + label
        var items = [
            URLQueryItem(name: "secret", value: Base32.encode(secret)),
            URLQueryItem(name: "digits", value: String(digits)),
            URLQueryItem(name: "algorithm", value: algorithm.name),
        ]
        if let issuer { items.append(URLQueryItem(name: "issuer", value: issuer)) }
        switch kind {
        case .totp: items.append(URLQueryItem(name: "period", value: String(Int(period))))
        case .hotp: items.append(URLQueryItem(name: "counter", value: String(counter)))
        }
        components.queryItems = items
        return components.string ?? ""
    }

    /// The current one-time code.
    public func currentCode(date: Date = Date()) -> String {
        switch kind {
        case .totp: return TOTP.code(secret: secret, date: date, period: period, digits: digits, algorithm: algorithm)
        case .hotp: return HOTP.code(secret: secret, counter: counter, digits: digits, algorithm: algorithm)
        }
    }
}
