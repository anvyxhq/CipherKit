// swift-tools-version: 5.9
import PackageDescription

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
        .target(name: "AnvyxCipherKit"),
        .target(name: "AnvyxCipherFile", dependencies: ["AnvyxCipherKit"]),
        .target(name: "AnvyxCipherBiometric", dependencies: ["AnvyxCipherKit"]),
        .target(name: "AnvyxCipherServer", dependencies: ["AnvyxCipherKit"]),
        .testTarget(name: "AnvyxCipherKitTests", dependencies: ["AnvyxCipherKit"]),
        .testTarget(name: "AnvyxCipherFileTests", dependencies: ["AnvyxCipherFile"]),
        .testTarget(name: "AnvyxCipherBiometricTests", dependencies: ["AnvyxCipherBiometric"]),
        .testTarget(name: "AnvyxCipherServerTests", dependencies: ["AnvyxCipherServer"]),
    ]
)
