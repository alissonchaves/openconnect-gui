// swift-tools-version: 5.9
import PackageDescription
import Foundation

let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let repositoryRoot = packageDirectory.deletingLastPathComponent()
let defaultCoreLibraryDirs = [
    repositoryRoot.appendingPathComponent("build-native-core").path
]
let coreLibraryDir = ProcessInfo.processInfo.environment["OPENCONNECT_CORE_LIBRARY_DIR"]
    ?? defaultCoreLibraryDirs.first(where: { FileManager.default.fileExists(atPath: $0) })
    ?? defaultCoreLibraryDirs[0]
func brewPrefix(_ formula: String) -> String? {
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/brew")
    process.arguments = ["--prefix", formula]
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return nil }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    return String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

let dependencyLibraryDir = ProcessInfo.processInfo.environment["OPENCONNECT_DEPENDENCY_LIBRARY_DIR"]
    ?? brewPrefix("openconnect").map { "\($0)/lib" }
    ?? "/opt/homebrew/opt/openconnect/lib"
let gnutlsLibraryDir = ProcessInfo.processInfo.environment["GNUTLS_LIBRARY_DIR"]
    ?? brewPrefix("gnutls").map { "\($0)/lib" }
    ?? "/opt/homebrew/opt/gnutls/lib"

let package = Package(
    name: "OpenConnectMac",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "OpenConnectMac", targets: ["OpenConnectMac"])
    ],
    targets: [
        .target(
            name: "OpenConnectCoreC",
            path: "CoreBridge",
            publicHeadersPath: "include",
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.macOS])),
                .unsafeFlags(["-L\(coreLibraryDir)", "-L\(dependencyLibraryDir)", "-L\(gnutlsLibraryDir)"], .when(platforms: [.macOS])),
                .linkedLibrary("openconnect-core", .when(platforms: [.macOS])),
                .linkedLibrary("c++", .when(platforms: [.macOS])),
                .linkedLibrary("openconnect", .when(platforms: [.macOS])),
                .linkedLibrary("gnutls", .when(platforms: [.macOS]))
            ]
        ),
        .executableTarget(
            name: "OpenConnectMac",
            dependencies: ["OpenConnectCoreC"],
            path: ".",
            exclude: ["README.md", "Package.swift", "CoreBridge", "Assets", "build-native-app.sh", "build-native-release.sh", "install-native-app.sh", "bundle-homebrew-dependencies.sh", "update-build-dependencies.sh", "Brewfile.native"]
        )
    ]
)
