// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "HankoPasskeyKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "HankoPasskeyKit", targets: ["HankoPasskeyKit"])
    ],
    targets: [
        .target(name: "HankoPasskeyKit", path: "Sources/HankoPasskeyKit"),
        .testTarget(name: "HankoPasskeyKitTests", dependencies: ["HankoPasskeyKit"], path: "Tests/HankoPasskeyKitTests"),
    ]
)
