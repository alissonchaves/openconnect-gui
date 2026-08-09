#!/bin/sh
set -eu

if ! command -v brew >/dev/null 2>&1; then
    echo "error: Homebrew is required to update native build dependencies" >&2
    exit 1
fi

brew update
brew bundle --file="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/Brewfile.native"

outdated="$(brew outdated --formula cmake pkg-config openconnect gnutls openvpn || true)"
if [ -n "$outdated" ]; then
    echo "Updating native build dependencies:"
    echo "$outdated"
    brew upgrade cmake pkg-config openconnect gnutls openvpn
else
    echo "Native build dependencies are up to date."
fi

for tool in cmake pkg-config openconnect openvpn; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '%-12s %s\n' "$tool" "$($tool --version 2>/dev/null | head -1)"
    fi
done
gnutls-cli --version 2>/dev/null | head -1 || true
