// swift-tools-version: 6.2
import PackageDescription

let concurrencyBaseline: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .defaultIsolation(nil),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
]

let package = Package(
    name: "CipherKit",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(name: "AnvyxCipherKit", targets: ["AnvyxCipherKit"]),
        .library(name: "AnvyxCipherFile", targets: ["AnvyxCipherFile"]),
        .library(name: "AnvyxCipherBiometric", targets: ["AnvyxCipherBiometric"]),
        .library(name: "AnvyxCipherServer", targets: ["AnvyxCipherServer"]),
    ],
    targets: [
        .target(name: "AnvyxCipherKit", swiftSettings: concurrencyBaseline),
        .target(name: "AnvyxCipherFile", dependencies: ["AnvyxCipherKit"], swiftSettings: concurrencyBaseline),
        .target(name: "AnvyxCipherBiometric", dependencies: ["AnvyxCipherKit"], swiftSettings: concurrencyBaseline),
        .target(name: "AnvyxCipherServer", dependencies: ["AnvyxCipherKit"], swiftSettings: concurrencyBaseline),
        .testTarget(name: "AnvyxCipherKitTests", dependencies: ["AnvyxCipherKit"], swiftSettings: concurrencyBaseline),
        .testTarget(name: "AnvyxCipherFileTests", dependencies: ["AnvyxCipherFile"], swiftSettings: concurrencyBaseline),
        .testTarget(name: "AnvyxCipherBiometricTests", dependencies: ["AnvyxCipherBiometric"], swiftSettings: concurrencyBaseline),
        .testTarget(name: "AnvyxCipherServerTests", dependencies: ["AnvyxCipherServer"], swiftSettings: concurrencyBaseline),
    ]
)
