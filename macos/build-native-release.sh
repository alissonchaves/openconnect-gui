#!/bin/sh
set -eu

package_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output="${1:-$package_root/dist}"

if [ "${SKIP_BREW_UPDATE:-0}" != "1" ]; then
    "$package_root/macos/update-build-dependencies.sh"
fi

core_build="$package_root/build-native-core"
cmake -S "$package_root/core" -B "$core_build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=26.0
cmake --build "$core_build" --target openconnect-core-helper openvpn-core-helper

OPENCONNECT_CORE_LIBRARY_DIR="$core_build" \
OPENCONNECT_CORE_HELPER="$core_build/openconnect-core-helper" \
OPENVPN_CORE_HELPER="$core_build/openvpn-core-helper" \
  "$package_root/macos/build-native-app.sh" "$output" release

version="${APP_VERSION:-2.0.0}"
archive="$(dirname "$output")/openconnect-gui-${version}-macos-arm64.zip"
checksum="${archive}.sha256"

ditto -c -k --sequesterRsrc --keepParent \
    "$output/OpenConnectMac.app" "$archive"
shasum -a 256 "$archive" > "$checksum"

echo "Archive: $archive"
echo "SHA-256: $(cut -d ' ' -f 1 "$checksum")"
