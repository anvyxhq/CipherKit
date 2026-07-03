// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CipherKit",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        // Core crypto primitives.
        .library(name: "CipherKit", targets: ["CipherKit"]),
        // Chunked encrypted file storage + key rotation (depends on core).
        .library(name: "CipherFile", targets: ["CipherFile"]),
        // Face ID / Touch ID gated Secure Enclave keys (depends on core).
        .library(name: "CipherBiometric", targets: ["CipherBiometric"]),
        // Server-facing helpers: JWT signing, RSA private-key ops, TLS pinning.
        .library(name: "CipherServer", targets: ["CipherServer"]),
    ],
    targets: [
        .target(name: "CipherKit"),
        .target(name: "CipherFile", dependencies: ["CipherKit"]),
        .target(name: "CipherBiometric", dependencies: ["CipherKit"]),
        .target(name: "CipherServer", dependencies: ["CipherKit"]),
        .testTarget(name: "CipherKitTests", dependencies: ["CipherKit"]),
        .testTarget(name: "CipherFileTests", dependencies: ["CipherFile"]),
        .testTarget(name: "CipherBiometricTests", dependencies: ["CipherBiometric"]),
        .testTarget(name: "CipherServerTests", dependencies: ["CipherServer"]),
    ]
)
