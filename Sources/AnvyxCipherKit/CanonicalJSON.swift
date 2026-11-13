//
//  CanonicalJSON.swift
//  CipherKit
//

import Foundation

/// Deterministic JSON encoding — the same value always produces the same
/// bytes, so the output can be hashed, signed or MAC'd and verified on another
/// platform.
///
/// ```swift
/// let bytes = try CanonicalJSON.encode(["b": 1, "a": ["x", true, NSNull()]])
/// // {"a":["x",true,null],"b":1}
/// ```
///
/// Rules:
/// - Object keys are sorted by their UTF-8 bytes.
/// - No whitespace.
/// - Strings are UTF-8 with minimal escaping: only `"`, `\` and control
///   characters below U+0020 (`\b \t \n \f \r`, otherwise `\u00xx`). `/` and
///   non-ASCII characters are written as-is. No Unicode normalization.
/// - Numbers are integers only. Floating-point values — including whole ones
///   such as `1.0`, and NaN / infinity — are rejected instead of being
///   formatted in a way another implementation might not reproduce.
///
/// Accepted values: `NSNull`, `Bool`, integer types, `String`, arrays, and
/// dictionaries with `String` keys. Anything else throws (fail closed).
public enum CanonicalJSON {

    public enum Failure: Error, Equatable {
        /// A floating-point, decimal or non-finite number.
        case nonIntegerNumber
        /// A value that is not null, a boolean, an integer, a string, an array
        /// or a string-keyed dictionary.
        case unsupportedValue
    }

    /// Canonical UTF-8 bytes of a JSON value.
    public static func encode(_ value: Any) throws -> Data {
        var output: [UInt8] = []
        try write(value, to: &output)
        return Data(output)
    }

    /// Canonical form as a `String`.
    public static func string(_ value: Any) throws -> String {
        String(decoding: try encode(value), as: UTF8.self)
    }

    // MARK: - Writer

    private static func write(_ value: Any, to output: inout [UInt8]) throws {
        if value is NSNull {
            output.append(contentsOf: "null".utf8)
        } else if let string = value as? String {
            write(string, to: &output)
        } else if let number = value as? NSNumber {
            try write(number, to: &output)
        } else if let object = value as? [String: Any] {
            output.append(UInt8(ascii: "{"))
            let keys = object.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            for (index, key) in keys.enumerated() {
                guard let member = object[key] else { continue }
                if index > 0 { output.append(UInt8(ascii: ",")) }
                write(key, to: &output)
                output.append(UInt8(ascii: ":"))
                try write(member, to: &output)
            }
            output.append(UInt8(ascii: "}"))
        } else if let array = value as? [Any] {
            output.append(UInt8(ascii: "["))
            for (index, element) in array.enumerated() {
                if index > 0 { output.append(UInt8(ascii: ",")) }
                try write(element, to: &output)
            }
            output.append(UInt8(ascii: "]"))
        } else {
            throw Failure.unsupportedValue
        }
    }

    private static func write(_ number: NSNumber, to output: inout [UInt8]) throws {
        if CFGetTypeID(number) == CFBooleanGetTypeID() {
            output.append(contentsOf: (number.boolValue ? "true" : "false").utf8)
            return
        }
        // objCType: c s i l q = signed, C S I L Q = unsigned; everything else
        // (f, d, NSDecimalNumber) is not an integer.
        switch String(cString: number.objCType) {
        case "c", "s", "i", "l", "q":
            output.append(contentsOf: String(number.int64Value).utf8)
        case "C", "S", "I", "L", "Q":
            output.append(contentsOf: String(number.uint64Value).utf8)
        default:
            throw Failure.nonIntegerNumber
        }
    }

    private static func write(_ string: String, to output: inout [UInt8]) {
        output.append(UInt8(ascii: "\""))
        for byte in string.utf8 {
            switch byte {
            case UInt8(ascii: "\""): output.append(contentsOf: #"\""#.utf8)
            case UInt8(ascii: "\\"): output.append(contentsOf: #"\\"#.utf8)
            case 0x08: output.append(contentsOf: #"\b"#.utf8)
            case 0x09: output.append(contentsOf: #"\t"#.utf8)
            case 0x0a: output.append(contentsOf: #"\n"#.utf8)
            case 0x0c: output.append(contentsOf: #"\f"#.utf8)
            case 0x0d: output.append(contentsOf: #"\r"#.utf8)
            case 0x00..<0x20:
                let hex = Array("0123456789abcdef".utf8)
                output.append(contentsOf: #"\u00"#.utf8)
                output.append(hex[Int(byte >> 4)])
                output.append(hex[Int(byte & 0x0f)])
            default: output.append(byte)
            }
        }
        output.append(UInt8(ascii: "\""))
    }
}
