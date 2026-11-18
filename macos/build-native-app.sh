#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 /path/to/output [debug|release]" >&2
    exit 2
fi

if command -v brew >/dev/null 2>&1; then
    brew_openconnect_prefix="$(brew --prefix openconnect 2>/dev/null || true)"
    brew_gnutls_prefix="$(brew --prefix gnutls 2>/dev/null || true)"
    : "${OPENCONNECT_DEPENDENCY_LIBRARY_DIR:=${brew_openconnect_prefix:+$brew_openconnect_prefix/lib}}"
    : "${GNUTLS_LIBRARY_DIR:=${brew_gnutls_prefix:+$brew_gnutls_prefix/lib}}"
    export OPENCONNECT_DEPENDENCY_LIBRARY_DIR GNUTLS_LIBRARY_DIR
fi

output="$1"
configuration="${2:-release}"
bundle_version="${APP_BUNDLE_VERSION:-$(date +%s)}"
app_version="${APP_VERSION:-2.1.0}"
# Release bundles are self-contained by default. Set this to 0 only for a
# development build that intentionally uses Homebrew at runtime.
BUNDLE_HOMEBREW_DEPENDENCIES="${BUNDLE_HOMEBREW_DEPENDENCIES:-1}"
MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
export MACOSX_DEPLOYMENT_TARGET
icon_resource="OpenConnectIcon-${bundle_version}"
package_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
binary_dir="$(swift build --package-path "$package_root" -c "$configuration" --show-bin-path)"
binary="$binary_dir/OpenConnectMac"

swift build --package-path "$package_root" -c "$configuration" \
    -Xswiftc -target -Xswiftc "arm64-apple-macosx${MACOSX_DEPLOYMENT_TARGET}"
if [ ! -x "$binary" ]; then
    echo "Swift executable not found: $binary" >&2
    exit 1
fi

bundle="$output/OpenConnectMac.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$binary" "$bundle/Contents/MacOS/OpenConnectMac"

# Build the application icon from the native vector symbol.
icon_work="$(mktemp -d /tmp/openconnect-icon.XXXXXX)"
trap 'rm -rf "$icon_work"' EXIT
mkdir -p "$icon_work/OpenConnectIcon.iconset"
for size in 16 32 128 256 512; do
    sips -s format png "$package_root/Assets/OpenConnectIcon.svg" --out "$icon_work/OpenConnectIcon.iconset/icon_${size}x${size}.png" --resampleHeightWidth "$size" "$size" >/dev/null
    double=$((size * 2))
    sips -s format png "$package_root/Assets/OpenConnectIcon.svg" --out "$icon_work/OpenConnectIcon.iconset/icon_${size}x${size}@2x.png" --resampleHeightWidth "$double" "$double" >/dev/null
done
iconutil -c icns "$icon_work/OpenConnectIcon.iconset" -o "$bundle/Contents/Resources/$icon_resource.icns"

core_helper="${OPENCONNECT_CORE_HELPER:-}"
if [ -z "$core_helper" ] && [ -n "${OPENCONNECT_CORE_LIBRARY_DIR:-}" ]; then
    core_helper="$(dirname -- "$OPENCONNECT_CORE_LIBRARY_DIR")/bin/openconnect-core-helper"
fi
if [ -n "$core_helper" ] && [ -x "$core_helper" ]; then
    cp "$core_helper" "$bundle/Contents/MacOS/openconnect-core-helper"
else
    echo "error: openconnect-core-helper not found; build the CMake core helpers first" >&2
    exit 1
fi

openvpn_helper="${OPENVPN_CORE_HELPER:-}"
if [ -z "$openvpn_helper" ] && [ -n "${OPENCONNECT_CORE_LIBRARY_DIR:-}" ]; then
    openvpn_helper="$(dirname -- "$OPENCONNECT_CORE_LIBRARY_DIR")/bin/openvpn-core-helper"
fi
if [ -n "$openvpn_helper" ] && [ -x "$openvpn_helper" ]; then
    cp "$openvpn_helper" "$bundle/Contents/MacOS/openvpn-core-helper"
else
    echo "error: openvpn-core-helper not found; build the CMake core helpers first" >&2
    exit 1
fi

cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>OpenConnect VPN</string>
    <key>CFBundleExecutable</key>
    <string>OpenConnectMac</string>
    <key>CFBundleIdentifier</key>
    <string>net.openconnect-vpn.gui.native.notifications</string>
    <key>CFBundleName</key>
    <string>OpenConnect VPN</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>CFBundleShortVersionString</key>
    <string>APP_VERSION_PLACEHOLDER</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleIconFile</key>
    <string>OpenConnectIcon</string>
    <key>CFBundleIconName</key>
    <string>OpenConnectIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>26.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSUserNotificationAlertStyle</key>
    <string>alert</string>
    <key>NSUserNotificationsUsageDescription</key>
    <string>OpenConnect VPN uses notifications to report VPN connection and disconnection events.</string>
</dict>
</plist>
PLIST

/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $app_version" "$bundle/Contents/Info.plist"
# The notification center caches the icon by bundle identifier and version.
# Bump the bundle version for each local build so the current icon is used
# while retaining the existing notification permission for this bundle ID.
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $bundle_version" "$bundle/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIconFile $icon_resource" "$bundle/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIconName $icon_resource" "$bundle/Contents/Info.plist"

script="${OPENCONNECT_VPNC_SCRIPT:-}"
if [ -z "$script" ]; then
    for candidate in \
        /opt/homebrew/etc/vpnc/vpnc-script \
        /usr/local/etc/vpnc/vpnc-script \
        /usr/share/vpnc-scripts/vpnc-script; do
        if [ -x "$candidate" ]; then script="$candidate"; break; fi
    done
fi

if [ -n "$script" ] && [ -x "$script" ]; then
    install -m 755 "$script" "$bundle/Contents/Resources/vpnc-script"
else
    echo "warning: vpnc-script not found; bundle requires it at runtime" >&2
fi

if [ "${BUNDLE_HOMEBREW_DEPENDENCIES:-0}" = "1" ]; then
    openvpn_binary="${OPENVPN_BINARY:-}"
    if [ -z "$openvpn_binary" ] && command -v brew >/dev/null 2>&1; then
        openvpn_prefix="$(brew --prefix openvpn 2>/dev/null || true)"
        if [ -n "$openvpn_prefix" ] && [ -x "$openvpn_prefix/sbin/openvpn" ]; then
            openvpn_binary="$openvpn_prefix/sbin/openvpn"
        fi
    fi
    if [ -z "$openvpn_binary" ]; then
        for candidate in /opt/homebrew/sbin/openvpn /usr/local/sbin/openvpn; do
            if [ -x "$candidate" ]; then openvpn_binary="$candidate"; break; fi
        done
    fi
    if [ -z "$openvpn_binary" ] || [ ! -x "$openvpn_binary" ]; then
        echo "error: OpenVPN executable not found; install Homebrew openvpn or set OPENVPN_BINARY" >&2
        exit 1
    fi
    install -m 755 "$openvpn_binary" "$bundle/Contents/MacOS/openvpn"
    "$package_root/bundle-homebrew-dependencies.sh" "$bundle"
fi

signing_identity="${CODESIGN_IDENTITY:--}"
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
    codesign --force --deep --options runtime --sign "$signing_identity" "$bundle"
else
    # Homebrew libraries have their own signing identity. Do not enable
    # Hardened Runtime for local ad-hoc builds, otherwise dyld rejects those
    # libraries for having a different Team ID.
    codesign --force --deep --sign - "$bundle"
fi

echo "Built $bundle"
