# Building release version and create a package 

## Version scheme

and main programming activities are in 'main' or 'feature/*' branches.
Version string auto=generated on compilation from Git info into following format:

    <major>.<minor>.<patch>[-rev_count-sha1][-dirty]

## Building packages

Always check if you have committed all changes or move work-in-progress work into stash!!
Following steps illustrate how to create application:

    $ git clone https://gitlab.com/openconnect/openconnect-gui
    $ cd openconnect-gui

To build a release package, review released changes in `CHANGELOG.md`,
update planned release version in `CMakeLists.txt`, commit and start a release
process with target tag:

    $ git checkout main
    $ ./release.sh X.Y.Z

Note that this requires to have a gitlab token with permissions to release
at ~/.gitlab-token as well as the necessary credentials for
casper.infradead.org.


### Release process

The version number in CMakeLists.txt should be updated to the
next release number at the time of release (this allows users
using development builds to receive notifications).

After bumping the version and committing, the `release.sh` script
should be run and this takes care of:
 - Creating a tag
 - Building released packages on gitlab CI
 - Uploading the packages to casper.infradead.org
 - Creating a gitlab release
 - Copying the relevant changelong entries to release description

## macOS release artifacts for Homebrew cask

When a tag is pushed, CI job `MacOSRelease` builds a self-contained
`OpenConnect-GUI.app` and exports:

- `openconnect-gui-<version>-macos-<arch>.zip`
- `openconnect-gui-<version>-macos-<arch>.zip.sha256`

These artifacts are produced after `macdeployqt` + `macdeployqtfix`, so the app
does not require Homebrew runtime dependencies (`qt`, `openconnect`, `gnutls`)
on the target machine.

Suggested cask strategy:

1. Upload the generated `.zip` to the **GitLab Package Registry**.
2. If public access to the Generic Registry is not available, use a public
   `package_files/<id>/download` URL in the cask (note that the ID changes per upload).
3. Use `depends_on macos: ">= :catalina"` in the cask.

This avoids breakage caused by missing/expired CI artifacts or private uploads.

### Manual macOS release build + GitHub asset (local)

If you need to build and publish the macOS asset manually (local machine),
the minimal flow is:

```
cmake -S . -B build
cmake --build build -j

cd build
QT_VERSION=$(brew list qt@6 --versions | awk '{print $2}')
/opt/homebrew/opt/qt/bin/macdeployqt ./bin/OpenConnect-GUI.app -verbose=2
curl -fsSL -o macdeployqtfix.py https://raw.githubusercontent.com/arl/macdeployqtfix/refs/heads/master/macdeployqtfix.py
python3 macdeployqtfix.py ./bin/OpenConnect-GUI.app /opt/homebrew/Cellar/qt/$QT_VERSION/
codesign --force --deep -s - ./bin/OpenConnect-GUI.app

VERSION=1.6.3
ARCH=$(uname -m)
PKG=openconnect-gui-${VERSION}-macos-${ARCH}.zip
ditto -c -k --sequesterRsrc --keepParent ./bin/OpenConnect-GUI.app "./${PKG}"
```

Then upload the ZIP and replace the asset on the GitHub release `v<version>`.
Keep a local token in `.github-token` (ignored by git) and use it to update
the asset.

## macOS signing and notarization (CI)

`MacOSRelease` supports signing + notarization when the following CI variables
are provided:

Signing (required for notarization):

- `MACOS_SIGNING_CERT_B64` base64-encoded `.p12` (Developer ID Application)
- `MACOS_SIGNING_CERT_PASSWORD` password for the `.p12`
- `MACOS_SIGNING_IDENTITY` codesign identity (e.g. `Developer ID Application: ...`)
- `MACOS_KEYCHAIN_PASSWORD` temporary keychain password used in CI

Notarization (choose one method):

App Store Connect API key:

- `NOTARY_KEY_B64` base64-encoded `.p8`
- `NOTARY_KEY_ID`
- `NOTARY_ISSUER_ID`

Apple ID:

- `NOTARY_APPLE_ID`
- `NOTARY_TEAM_ID`
- `NOTARY_APP_PASSWORD` (app-specific password)

If these variables are not set, CI falls back to ad-hoc signing which triggers
Gatekeeper warnings on other machines.
