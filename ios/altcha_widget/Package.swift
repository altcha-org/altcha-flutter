// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "altcha_widget",
  platforms: [
    .iOS("12.0"),
  ],
  products: [
    .library(name: "altcha_widget", targets: ["altcha_widget"]),
  ],
  targets: [
    .target(
      name: "altcha_widget",
      dependencies: [],
      path: "../Classes",
      publicHeadersPath: "."
    ),
  ],
  cxxLanguageStandard: .cxx17
)
