// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftPQCLI",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(name: "SwiftPQ", targets: ["SwiftPQ"]),
        .executable(name: "SwiftPQCLI", targets: ["SwiftPQCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "3.0.0"),
    ],
    targets: [
        .target(name: "CPQ", path: "./Sources/CPQ"),
        .target(name: "SwiftPQ", dependencies: [
            "CPQ",
            .product(name: "Crypto", package: "swift-crypto")
        ]),
        .executableTarget(name: "SwiftPQCLI", dependencies: [
            "CPQ",
            "SwiftPQ",
            .product(name: "ArgumentParser", package: "swift-argument-parser"),            
        ]),
    ]
)
