import XCTest
@testable import AnvyxCipherKit

final class CanonicalJSONTests: XCTestCase {

    func testVectors() throws {
        let vectors: [(Any, String)] = [
            (NSNull(), "null"),
            (true, "true"),
            (false, "false"),
            (0, "0"),
            (-42, "-42"),
            (Int64.min, "-9223372036854775808"),
            (UInt64.max, "18446744073709551615"),
            (UInt8(7), "7"),
            ("", #""""#),
            ("a/b", #""a/b""#),
            ("q\"b\\", #""q\"b\\""#),
            ("\u{08}\t\n\u{0c}\r\u{01}\u{1f}", #""\b\t\n\f\r\u0001\u001f""#),
            ("é€😀\u{7f}", "\"é€😀\u{7f}\""),
            ([Any](), "[]"),
            ([String: Any](), "{}"),
            ([1, "a", NSNull(), [true]] as [Any], #"[1,"a",null,[true]]"#),
            (["b": 2, "a": 1, "aa": 3, "B": 4, "": 5], #"{"":5,"B":4,"a":1,"aa":3,"b":2}"#),
            (["z": ["y": [1, 2], "x": "v"], "a": false] as [String: Any], #"{"a":false,"z":{"x":"v","y":[1,2]}}"#),
        ]
        for (value, expected) in vectors {
            XCTAssertEqual(try CanonicalJSON.string(value), expected)
        }
    }

    /// U+FF5E (EF BD 9E) sorts before U+1F600 (F0 9F 98 80) by UTF-8 bytes,
    /// the opposite of UTF-16 code-unit order.
    func testKeysSortByUTF8Bytes() throws {
        let value: [String: Any] = ["😀": 1, "～": 2, "é": 3, "z": 4]
        XCTAssertEqual(try CanonicalJSON.string(value), #"{"z":4,"é":3,"～":2,"😀":1}"#)
    }

    func testOutputIsStableAcrossInsertionOrder() throws {
        var first: [String: Any] = [:], second: [String: Any] = [:]
        let keys = (0..<50).map { "k\($0)" }
        for key in keys { first[key] = 1 }
        for key in keys.reversed() { second[key] = 1 }
        XCTAssertEqual(try CanonicalJSON.encode(first), try CanonicalJSON.encode(second))
    }

    func testParsedJSONRoundTrip() throws {
        let parsed = try JSONSerialization.jsonObject(with: Data(#"{ "b" : [ 1 , true ] , "a" : "x\/y" }"#.utf8))
        XCTAssertEqual(try CanonicalJSON.string(parsed), #"{"a":"x/y","b":[1,true]}"#)
    }

    func testFloatsAreRejected() {
        let floats: [Any] = [1.5, 1.0, Float(2), Double.nan, Double.infinity, -Double.infinity,
                             Decimal(3), NSDecimalNumber(string: "1"), ["a": [0.1]]]
        for value in floats {
            XCTAssertThrowsError(try CanonicalJSON.encode(value)) {
                XCTAssertEqual($0 as? CanonicalJSON.Failure, .nonIntegerNumber, "\(value)")
            }
        }
        for text in ["1.0", "1e2", "[0.5]", "123456789012345678901234567890"] {
            let parsed = try! JSONSerialization.jsonObject(with: Data(text.utf8), options: .fragmentsAllowed)
            XCTAssertThrowsError(try CanonicalJSON.encode(parsed), text)
        }
    }

    func testUnsupportedValuesAreRejected() {
        let values: [Any] = [Date(), Data([1]), [1: "a"], ["a": Date()], Optional<Int>.none as Any, URL(fileURLWithPath: "/")]
        for value in values {
            XCTAssertThrowsError(try CanonicalJSON.encode(value)) {
                XCTAssertEqual($0 as? CanonicalJSON.Failure, .unsupportedValue, "\(value)")
            }
        }
    }
}
