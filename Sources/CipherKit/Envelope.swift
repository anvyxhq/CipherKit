//
//  Envelope.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  Envelope encryption: encrypt data with a random per-message data key, then
//  wrap that data key with a master key (KEK). Rotating the master only
//  re-wraps the small key — no need to re-encrypt large payloads.

import Foundation
import CryptoKit

public enum Envelope {

    public struct Sealed: Codable, Equatable {
        public let wrappedKey: Data   // data key, encrypted under the master
        public let ciphertext: Data   // payload, encrypted under the data key
    }

    public static func seal(_ data: Data, master: SymmetricKey) throws -> Sealed {
        let dataKey = AESGCM.randomKey()
        let ciphertext = try AESGCM.seal(data, using: dataKey)
        let wrappedKey = try AESGCM.seal(dataKey.withUnsafeBytes { Data($0) }, using: master)
        return Sealed(wrappedKey: wrappedKey, ciphertext: ciphertext)
    }

    public static func open(_ sealed: Sealed, master: SymmetricKey) throws -> Data {
        let dataKeyData = try AESGCM.open(sealed.wrappedKey, using: master)
        return try AESGCM.open(sealed.ciphertext, using: SymmetricKey(data: dataKeyData))
    }

    /// Rotate the master key by re-wrapping only the data key — the (possibly
    /// huge) ciphertext is left untouched.
    public static func rewrap(_ sealed: Sealed, from oldMaster: SymmetricKey, to newMaster: SymmetricKey) throws -> Sealed {
        let dataKeyData = try AESGCM.open(sealed.wrappedKey, using: oldMaster)
        let rewrapped = try AESGCM.seal(dataKeyData, using: newMaster)
        return Sealed(wrappedKey: rewrapped, ciphertext: sealed.ciphertext)
    }
}
