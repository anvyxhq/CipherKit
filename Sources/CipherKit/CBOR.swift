//
//  CBOR.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  Minimal CBOR (RFC 8949) decoder — enough for App Attest attestation objects
//  (unsigned/negative ints, byte/text strings, arrays, text-keyed maps, simple).

import Foundation

public indirect enum CBORValue: Equatable {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case map([String: CBORValue])
    case bool(Bool)
    case null
}

public enum CBOR {
    /// Decode a single top-level CBOR item. Returns `nil` on malformed input.
    public static func decode(_ data: Data) -> CBORValue? {
        var index = data.startIndex
        return decodeItem(data, &index)
    }

    private static func decodeItem(_ data: Data, _ i: inout Data.Index) -> CBORValue? {
        guard i < data.endIndex else { return nil }
        let initial = data[i]
        i = data.index(after: i)
        let major = initial >> 5
        let info = initial & 0x1f

        func length() -> UInt64? {
            switch info {
            case 0..<24: return UInt64(info)
            case 24: return readUInt(data, &i, 1)
            case 25: return readUInt(data, &i, 2)
            case 26: return readUInt(data, &i, 4)
            case 27: return readUInt(data, &i, 8)
            default: return nil
            }
        }

        switch major {
        case 0: return length().map { .unsigned($0) }
        case 1: return length().map { .negative(-1 - Int64(bitPattern: $0)) }
        case 2: return length().flatMap { readBytes(data, &i, Int($0)) }.map { .bytes($0) }
        case 3:
            guard let n = length(), let raw = readBytes(data, &i, Int(n)),
                  let string = String(data: raw, encoding: .utf8) else { return nil }
            return .text(string)
        case 4:
            guard let n = length() else { return nil }
            var items: [CBORValue] = []
            for _ in 0..<n { guard let item = decodeItem(data, &i) else { return nil }; items.append(item) }
            return .array(items)
        case 5:
            guard let n = length() else { return nil }
            var map: [String: CBORValue] = [:]
            for _ in 0..<n {
                guard case let .text(key)? = decodeItem(data, &i),
                      let value = decodeItem(data, &i) else { return nil }
                map[key] = value
            }
            return .map(map)
        case 7:
            switch info { case 20: return .bool(false); case 21: return .bool(true); case 22: return .null; default: return nil }
        default:
            return nil
        }
    }

    private static func readUInt(_ data: Data, _ i: inout Data.Index, _ count: Int) -> UInt64? {
        guard let bytes = readBytes(data, &i, count) else { return nil }
        return bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private static func readBytes(_ data: Data, _ i: inout Data.Index, _ count: Int) -> Data? {
        guard count >= 0, let end = data.index(i, offsetBy: count, limitedBy: data.endIndex) else { return nil }
        let slice = data[i..<end]
        i = end
        return Data(slice)
    }
}
