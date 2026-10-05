// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "altcha_widget",
  platforms: [
    .macOS("10.14"),
  ],
  products: [
    .library(name: "altcha-widget", targets: ["altcha_widget"]),
  ],
  targets: [
    // ObjC++ PBKDF2 solver (shared C++ impl via symlinks to darwin/Classes).
    // Must be a separate target: SwiftPM does not allow mixed Swift and
    // C/ObjC source files within a single target.
    .target(
      name: "AltchaPbkdf2Bridge",
      dependencies: [],
      path: "Sources/AltchaPbkdf2Bridge",
      publicHeadersPath: ".",
      // Always optimize the PBKDF2 solver (also in Debug), matching Android/Linux -O3.
      cxxSettings: [.unsafeFlags(["-O3"])]
    ),
    .target(
      name: "altcha_widget",
      dependencies: ["AltchaPbkdf2Bridge"],
      path: "Sources/altcha_widget"
    ),
  ],
  cxxLanguageStandard: .cxx17
)
