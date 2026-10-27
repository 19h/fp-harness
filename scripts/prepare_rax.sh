#!/bin/sh
# Materialize the exact committed RAX dependency without touching its checkout.
set -eu
source_repo=${1:-/Users/int/dev/rax}
commit=ee96791b42237862178f1774afaf0f1ee8570ce9
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dest="$root/.deps/rax"
if [ -e "$dest" ]; then
    printf '%s\n' "Refusing to replace existing $dest" >&2
    exit 1
fi
mkdir -p "$root/.deps"
tmp=$(mktemp -d "$root/.deps/rax.tmp.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
git -C "$source_repo" cat-file -e "$commit^{commit}"
git -C "$source_repo" archive "$commit" Cargo.toml Cargo.lock README.md LICENSE THIRD_PARTY_NOTICES.md src capi | tar -xf - -C "$tmp"
printf '%s\n' "$commit" > "$tmp/FP_HARNESS_RAX_COMMIT"
mv "$tmp" "$dest"
trap - EXIT HUP INT TERM
printf 'Prepared RAX %s at %s\n' "$commit" "$dest"
