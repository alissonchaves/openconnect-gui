#!/bin/sh
set -eu

APP_PATH=${1:-"$(pwd)/build/bin/OpenConnect-GUI.app"}
if [ ! -d "$APP_PATH" ]; then
  echo "App not found: $APP_PATH" >&2
  exit 1
fi

# Remove bundled Qt bits so the dev build uses Homebrew Qt only.
rm -rf "$APP_PATH/Contents/Frameworks" \
       "$APP_PATH/Contents/PlugIns" \
       "$APP_PATH/Contents/Resources/qt.conf"

echo "Cleaned bundled Qt from: $APP_PATH"
