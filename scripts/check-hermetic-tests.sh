#!/usr/bin/env bash
# Run every library's unit tests in a sandbox with no network and a read-only
# filesystem, to prove they perform no socket or file I/O (issue #519).
#
# A unit test that opens a socket (loopback included), creates a temporary
# file or directory, or writes anywhere fails here with "Operation not
# permitted". Such a test belongs behind the crate's `integration` feature.
#
# The tests are built first, outside the sandbox, and the test binaries are
# then run inside it, each from its crate's directory as cargo would.
#
# Usage (from repo root):
#   ./scripts/check-hermetic-tests.sh                 whole workspace
#   ./scripts/check-hermetic-tests.sh -p hopf-ftp     one crate (repeatable)
#   ./scripts/check-hermetic-tests.sh -p hopf-ftp -- session_tests   filter
#
# Sandbox: macOS uses sandbox-exec, which denies every socket (a bare bind
# included) and every write. Linux unshares the network and mount namespaces
# (as root, through unprivileged user namespaces, or through sudo) and makes /
# read-only; the new network namespace has no usable interface, so a socket can
# be created and bound but nothing can connect or send. Only /dev stays
# writable.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD

packages=()
while [ $# -gt 0 ]; do
    case "$1" in
        -p|--package) packages+=(-p "$2"); shift 2 ;;
        --) shift; break ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
filter=("$@")
[ ${#packages[@]} -eq 0 ] && packages=(--workspace)

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

echo "building the unit tests..." >&2
cargo test "${packages[@]}" --lib --no-run --message-format=json 2>/dev/null |
    python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"] and "lib" in m["target"]["kind"]:
        print(m["executable"], m["manifest_path"].rsplit("/", 1)[0])
' > "$scratch/binaries"

case "$(uname -s)" in
    Darwin)
        cat > "$scratch/deny.sb" <<'EOF'
(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "/dev"))
EOF
        confine() { sandbox-exec -f "$scratch/deny.sb" "$@"; }
        ;;
    Linux)
        readonly_root='mount --make-rprivate / && mount -o remount,ro,bind / / && exec "$@"'
        if [ "$(id -u)" -eq 0 ]; then
            unshare_cmd=(unshare -m -n)
        elif unshare -r -m -n true 2>/dev/null; then
            unshare_cmd=(unshare -r -m -n)
        elif sudo -n true 2>/dev/null; then
            unshare_cmd=(sudo -n unshare -m -n)
        else
            echo "cannot create namespaces: need root, sudo or unprivileged user namespaces" >&2
            exit 2
        fi
        confine() { "${unshare_cmd[@]}" -- sh -c "$readonly_root" sh "$@"; }
        ;;
    *) echo "unsupported platform: $(uname -s)" >&2; exit 2 ;;
esac

failed=0
while read -r binary dir; do
    name=$(basename "$binary")
    log="$scratch/$name.log"
    if (cd "$dir" && confine env CARGO_MANIFEST_DIR="$dir" "$binary" --test-threads=8 ${filter[@]+"${filter[@]}"} > "$log" 2>&1); then
        echo "ok      ${dir#$ROOT/}"
    else
        echo "FAILED  ${dir#$ROOT/}"
        grep -E '^test .* FAILED$' "$log" | sed 's/^test /          /; s/ \.\.\. FAILED$//'
        if ! grep -q '^test .* FAILED$' "$log"; then
            tail -5 "$log" | sed 's/^/          /'
        fi
        failed=$((failed + 1))
    fi
done < "$scratch/binaries"

if [ "$failed" -ne 0 ]; then
    echo "$failed crate(s) have unit tests that do socket or file I/O" >&2
    exit 1
fi
