#!/bin/bash
set -euo pipefail

bundle="$1"
frameworks="$bundle/Contents/Frameworks"
mkdir -p "$frameworks"

is_system_path() {
    case "$1" in
        /System/*|/usr/lib/*|/usr/libexec/*) return 0 ;;
        *) return 1 ;;
    esac
}

declare -a queue=()
while IFS= read -r file; do queue+=("$file"); done < <(
    find "$bundle/Contents/MacOS" -type f -perm -111 -print
)

seen_dir="$(mktemp -d /tmp/openconnect-dylibs.XXXXXX)"
trap 'rm -rf "$seen_dir"' EXIT
while [ "${#queue[@]}" -gt 0 ]; do
    file="${queue[0]}"
    queue=("${queue[@]:1}")
    [ -f "$file" ] || continue
    marker="$seen_dir/$(printf '%s' "$file" | shasum | awk '{print $1}')"
    [ -e "$marker" ] && continue
    : > "$marker"

    while IFS= read -r dependency; do
        case "$dependency" in
            /*) ;;
            *) continue ;;
        esac
        is_system_path "$dependency" && continue
        [ -f "$dependency" ] || continue

        name="$(basename "$dependency")"
        destination="$frameworks/$name"
        if [ ! -e "$destination" ]; then
            cp -L "$dependency" "$destination"
            chmod 755 "$destination"
            install_name_tool -id "@rpath/$name" "$destination" 2>/dev/null || true
        fi
        install_name_tool -change "$dependency" "@rpath/$name" "$file" 2>/dev/null || true
        queue+=("$destination")
    done < <(otool -L "$file" | sed -n '2,$s/^[[:space:]]*\([^[:space:]]*\).*/\1/p')

    if file "$file" | grep -q 'Mach-O'; then
        install_name_tool -add_rpath "@loader_path/../Frameworks" "$file" 2>/dev/null || true
    fi
done

echo "Bundled Homebrew dylibs in $frameworks"
