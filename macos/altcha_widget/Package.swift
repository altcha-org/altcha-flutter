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
      publicHeadersPath: "."
    ),
    .target(
      name: "altcha_widget",
      dependencies: ["AltchaPbkdf2Bridge"],
      path: "Sources/altcha_widget"
    ),
  ],
  cxxLanguageStandard: .cxx17
)
