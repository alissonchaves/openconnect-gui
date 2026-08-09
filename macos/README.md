# OpenConnect for Mac — native macOS app

This directory contains the native SwiftUI/AppKit application and the C++ VPN
core. The macOS app uses the C bridge in `CoreBridge`.

## Requirements

- macOS 26 or newer (Darwin 25);
- Apple Silicon (ARM64);
- Xcode Command Line Tools, including Swift 5.9 or newer;
- CMake and a C++17 compiler;
- Homebrew packages `openconnect`, `gnutls`, and `openvpn` when building the
  release bundle;
- administrator authorization when macOS creates/configures the VPN tunnel.

The app uses the OpenConnect library built with GnuTLS and the OpenVPN
executable for OpenVPN profiles. Profiles and credentials are kept by the
native app; passwords are stored in the macOS Keychain.

## Build

Build the core first:

```bash
macos/update-build-dependencies.sh
cmake -S core -B build-native-core -DCMAKE_BUILD_TYPE=Release
cmake --build build-native-core --target openconnect-core-helper openvpn-core-helper
```

Then create the application bundle:

```bash
OPENCONNECT_CORE_LIBRARY_DIR="$PWD/build-native-core" \
OPENCONNECT_CORE_HELPER="$PWD/build-native-core/openconnect-core-helper" \
OPENVPN_CORE_HELPER="$PWD/build-native-core/openvpn-core-helper" \
  macos/build-native-app.sh /tmp/OpenConnect-for-Mac release
```

The script resolves Homebrew paths automatically. They can be overridden with
`OPENCONNECT_DEPENDENCY_LIBRARY_DIR`, `GNUTLS_LIBRARY_DIR`,
`OPENVPN_CORE_HELPER`, and `OPENCONNECT_VPNC_SCRIPT`.

For a self-contained bundle, copy the Homebrew dynamic-library closure into
the app with:

```bash
BUNDLE_HOMEBREW_DEPENDENCIES=1 \
OPENCONNECT_CORE_LIBRARY_DIR="$PWD/build-native-core" \
OPENCONNECT_CORE_HELPER="$PWD/build-native-core/openconnect-core-helper" \
OPENVPN_CORE_HELPER="$PWD/build-native-core/openvpn-core-helper" \
  macos/build-native-app.sh /tmp/OpenConnect-for-Mac release
```

For the complete release workflow, which updates Homebrew dependencies first:

```bash
macos/build-native-release.sh /tmp/OpenConnect-for-Mac
```

The release script also creates
`openconnect-gui-VERSION-macos-arm64.zip` and its `.sha256` file. Copy the
hash into `Casks/openconnect-gui.rb` before publishing the cask release.

Use `SKIP_BREW_UPDATE=1` when the build machine is intentionally pinned to
the currently installed tool versions.

For the distributed build, use the self-contained mode. It embeds OpenConnect,
GnuTLS, OpenVPN, `vpnc-script`, and their Homebrew dylib closure. Homebrew is
then only the installation/update channel; the cask has no runtime formula
dependencies.

## Install and test

```bash
macos/install-native-app.sh /tmp/OpenConnect-for-Mac/OpenConnectMac.app
open -a "OpenConnect for Mac"
```

The installer copies the app to `~/Applications/OpenConnect for Mac.app`,
registers it with LaunchServices, and removes the previous app and its
configuration files. Keychain credentials are preserved.

## Distribution

The repository's Homebrew cask is `Casks/openconnect-gui.rb`. It is ARM64-only
and has no runtime formula dependencies. Release archives should contain
`OpenConnectMac.app`; the cask renames it to **OpenConnect for Mac** when it is
installed.

For a signed release, set `CODESIGN_IDENTITY` before running the build script.
Without it, the script applies an ad-hoc signature suitable for local testing.

## TLS backend

GnuTLS is retained intentionally. OpenConnect expects a complete TLS/DTLS
backend with certificate handling, protocol features, and cipher support;
Apple's Network.framework is not a drop-in OpenConnect TLS backend. Replacing
GnuTLS would require maintaining a substantial OpenConnect fork and would
risk compatibility with the supported VPN providers. The native macOS UI and
the native C++ core uses GnuTLS for the VPN TLS library.
