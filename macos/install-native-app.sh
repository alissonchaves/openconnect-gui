#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/OpenConnectMac.app" >&2
    exit 2
fi

source_app="$1"
if [ ! -d "$source_app" ]; then
    echo "error: app bundle not found: $source_app" >&2
    exit 1
fi

# Remove only the known previous installation and its configuration files. The
# native app has separate UserDefaults storage. Credentials are intentionally
# kept in Keychain because the native app may reuse them.
legacy_paths="
/Applications/OpenConnect-GUI.app
$HOME/Applications/OpenConnect-GUI.app
$HOME/Library/Application Support/OpenConnect-GUI Team/OpenConnect-GUI
$HOME/Library/Application Support/OpenConnect-GUI Team/OpenConnect VPN
$HOME/Library/Preferences/gui.openconnect-vpn.net.OpenConnect-GUI.plist
$HOME/Library/Preferences/OpenConnect-GUI Team.OpenConnect-GUI.plist
"
echo "$legacy_paths" | while IFS= read -r legacy_path; do
    [ -n "$legacy_path" ] || continue
    if [ -e "$legacy_path" ]; then
        rm -rf -- "$legacy_path"
        echo "Removed previous application data: $legacy_path"
    fi
done

applications_dir="$HOME/Applications"
destination="$applications_dir/OpenConnect for Mac.app"
mkdir -p "$applications_dir"

# Keep the previous bundle recoverable rather than deleting it.
if [ -e "$destination" ]; then
    backup="${destination}.previous-$(date +%Y%m%d-%H%M%S)"
    mv "$destination" "$backup"
    echo "Previous app moved to $backup"
fi

ditto "$source_app" "$destination"

lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [ -x "$lsregister" ]; then
    "$lsregister" -f "$destination" >/dev/null 2>&1 || true
fi

echo "Installed $destination"
echo "Open with: open -a \"OpenConnect for Mac\""
