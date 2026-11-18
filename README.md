# OpenConnect for Mac

Native macOS VPN client for OpenConnect and OpenVPN, built with SwiftUI,
AppKit and a C++ core.

The current product targets Apple Silicon and macOS 26 or newer (Darwin 25).
The application bundle contains OpenConnect, GnuTLS, OpenVPN, `vpnc-script`
and the required dynamic libraries, so Homebrew is only needed to build or
install/update the release—not at runtime.

## Install with Homebrew

```bash
brew tap alissonchaves/openconnect-gui https://github.com/alissonchaves/openconnect-gui.git
brew install --cask openconnect-gui
```

Update the installed application:

```bash
brew update
brew upgrade --cask openconnect-gui
```

The installer removes the previous application and its known configuration
files, while preserving credentials stored in Keychain.

## Build and release

Install/update the build dependencies and create the complete release bundle:

```bash
macos/build-native-release.sh /tmp/OpenConnect-for-Mac
```

This updates Homebrew dependencies, compiles the native core, bundles all
runtime dependencies, signs the app, and generates:

- `openconnect-gui-VERSION-macos-arm64.zip`;
- `openconnect-gui-VERSION-macos-arm64.zip.sha256`.

Set the release version explicitly:

```bash
APP_VERSION=2.1.0 macos/build-native-release.sh /tmp/OpenConnect-for-Mac
```

For a build using the currently installed dependency versions:

```bash
SKIP_BREW_UPDATE=1 APP_VERSION=2.1.0 \
  macos/build-native-release.sh /tmp/OpenConnect-for-Mac
```

Publish the generated ZIP in the GitHub release tagged `vVERSION`, then copy
its SHA-256 into [`Casks/openconnect-gui.rb`](Casks/openconnect-gui.rb).

## Project layout

- `core/` — C++ VPN session and privileged helpers;
- `macos/` — SwiftUI/AppKit application, packaging and update tools;
- `Casks/` — Homebrew cask definition;
- `CHANGELOG.md` — release history;
- `LICENSE` and `LICENSE.txt` — project licenses.

Detailed macOS build notes are in [`macos/README.md`](macos/README.md).

## License

The project is licensed under the [GNU General Public License v2](LICENSE.txt).
