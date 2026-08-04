#!/usr/bin/env bash
# Publish all hopf workspace crates to crates.io in dependency order,
# sleeping between uploads according to crates.io rate-limit buckets.
#
# crates.io (https://crates.io/docs/rate-limits) — two separate meters:
#   brand-new crate names: burst 5, then ~1 every 10 minutes
#   new versions of existing crates: burst 30, then ~1 every minute
#
# Several hopf crates already exist; publishing a new version
# for those is an *update*. Crates that are not on crates.io at all are
# *new*.
# The script classifies each publish via the API and tracks the two buckets
# independently so an update does not force a long wait after a new crate
# (and vice versa).
#
# Defaults (conservative vs the documented floors):
#   --interval-new    20m   (new crate names)
#   --interval-update 90s   (version bumps of existing crates)
#   --interval DUR    sets both (legacy / blunt override)
#
# Usage (from repo root, with CARGO_REGISTRY_TOKEN set or `cargo login` done):
#   ./scripts/publish-crates.sh
#   ./scripts/publish-crates.sh --dry-run
#   ./scripts/publish-crates.sh --from hopf-http
#   ./scripts/publish-crates.sh --only hopf-ldap,hopf-amqp
#
# Target version already on crates.io → skip (no delay). On HTTP 429 the
# script parses Cargo's "try again after …" stamp and waits.
#
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

UA='hopf-publish-crates (https://github.com/cpkb-bluezoo/hopf)'

# Topological order: each crate's hopf-* deps appear earlier.
# Optional deps (e.g. hopf-dns → hopf-quic) are ordered as hard so feature
# builds and cargo publish verification succeed once the index has caught up.
CRATES=(
  hopf-core
  hopf-auth
  hopf-tls
  hopf-quic
  hopf-dns
  hopf-mailbox
  hopf-ldap
  hopf-http
  hopf-webdav
  hopf-websocket
  hopf-grpc
  hopf-otel
  hopf-ftp
  hopf-amqp
  hopf-smtp
  hopf-pop3
  hopf-imap
  hopf-mqtt
  hopf
)

INTERVAL_NEW_SECS=$((20 * 60))
INTERVAL_UPDATE_SECS=90
DRY_RUN=0
FROM=""
ONLY=""
VERSION=""
EXTRA_CARGO_ARGS=()

# Epoch seconds of last successful publish in each bucket (0 = none yet).
LAST_NEW_AT=0
LAST_UPDATE_AT=0

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

parse_duration() {
  local raw="$1"
  if [[ "$raw" =~ ^([0-9]+)s$ ]]; then
    echo "${BASH_REMATCH[1]}"
  elif [[ "$raw" =~ ^([0-9]+)m$ ]]; then
    echo $((BASH_REMATCH[1] * 60))
  elif [[ "$raw" =~ ^([0-9]+)h$ ]]; then
    echo $((BASH_REMATCH[1] * 3600))
  elif [[ "$raw" =~ ^[0-9]+$ ]]; then
    echo "$raw"
  else
    echo "error: bad duration '$raw' (use 120, 20m, 1h)" >&2
    exit 2
  fi
}

now_epoch() {
  date +%s
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --interval)
      INTERVAL_NEW_SECS="$(parse_duration "${2:?}")"
      INTERVAL_UPDATE_SECS="$INTERVAL_NEW_SECS"
      shift 2
      ;;
    --interval-new)
      INTERVAL_NEW_SECS="$(parse_duration "${2:?}")"
      shift 2
      ;;
    --interval-update)
      INTERVAL_UPDATE_SECS="$(parse_duration "${2:?}")"
      shift 2
      ;;
    --from)
      FROM="${2:?}"
      shift 2
      ;;
    --only)
      ONLY="${2:?}"
      shift 2
      ;;
    --version)
      VERSION="${2:?}"
      shift 2
      ;;
    --)
      shift
      EXTRA_CARGO_ARGS+=("$@")
      break
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage 2
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(
    python3 - <<'PY'
import re, pathlib
text = pathlib.Path("Cargo.toml").read_text()
m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text.split("[workspace.package]", 1)[1])
print(m.group(1) if m else "")
PY
  )"
fi
if [[ -z "$VERSION" ]]; then
  echo "error: could not read workspace version" >&2
  exit 1
fi

# Returns 0 if this exact version is already on crates.io.
crate_version_published() {
  local name="$1" ver="$2"
  local code
  code="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -H "User-Agent: ${UA}" \
      "https://crates.io/api/v1/crates/${name}/${ver}" || true
  )"
  [[ "$code" == "200" ]]
}

# Returns 0 if the crate name exists on crates.io (any version, e.g. 0.1.0).
crate_exists() {
  local name="$1"
  local code
  code="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -H "User-Agent: ${UA}" \
      "https://crates.io/api/v1/crates/${name}" || true
  )"
  [[ "$code" == "200" ]]
}

wait_secs() {
  local total="$1"
  local reason="${2:-rate limit}"
  if (( total <= 0 )); then
    return 0
  fi
  local until
  until="$(date -u -v+"${total}S" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null \
    || date -u -d "+${total} seconds" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null \
    || echo "+${total}s")"
  echo "==> sleeping ${total}s (${reason}); resume around ${until}"
  local left=$total
  while (( left > 0 )); do
    local chunk=$(( left < 30 ? left : 30 ))
    sleep "$chunk"
    left=$((left - chunk))
    if (( left > 0 )); then
      printf '    … %dm %ds remaining\n' $((left / 60)) $((left % 60))
    fi
  done
}

# Wait for the given bucket so we do not publish faster than its interval.
wait_for_bucket() {
  local kind="$1" # new | update
  local last interval
  if [[ "$kind" == "new" ]]; then
    last=$LAST_NEW_AT
    interval=$INTERVAL_NEW_SECS
  else
    last=$LAST_UPDATE_AT
    interval=$INTERVAL_UPDATE_SECS
  fi
  if (( last == 0 || DRY_RUN )); then
    return 0
  fi
  local elapsed=$(( $(now_epoch) - last ))
  local need=$(( interval - elapsed ))
  if (( need > 0 )); then
    wait_secs "$need" "${kind}-crate interval before next"
  fi
}

mark_bucket() {
  local kind="$1"
  local t
  t="$(now_epoch)"
  if [[ "$kind" == "new" ]]; then
    LAST_NEW_AT=$t
  else
    LAST_UPDATE_AT=$t
  fi
}

# Parse "Please try again after Tue, 04 Aug 2026 15:25:13 GMT" from cargo stderr.
secs_until_retry_after() {
  local log="$1"
  python3 - "$log" <<'PY'
import sys, re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
text = open(sys.argv[1], errors="replace").read()
m = re.search(r"try again after\s+(.+?)(?:\s+or\s+email|\.|$)", text, re.I | re.S)
if not m:
    sys.exit(1)
stamp = m.group(1).strip().rstrip(".")
try:
    when = parsedate_to_datetime(stamp)
except Exception:
    sys.exit(1)
if when.tzinfo is None:
    when = when.replace(tzinfo=timezone.utc)
now = datetime.now(timezone.utc)
delta = int((when - now).total_seconds()) + 5
print(max(delta, 60))
PY
}

fallback_interval_for() {
  local kind="$1"
  if [[ "$kind" == "new" ]]; then
    echo "$INTERVAL_NEW_SECS"
  else
    echo "$INTERVAL_UPDATE_SECS"
  fi
}

publish_one() {
  local name="$1"
  local kind="$2"
  local log
  log="$(mktemp -t "hopf-publish-${name}.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -f '$log'" RETURN

  echo "==> cargo publish -p ${name} (v${VERSION}, ${kind})"
  set +e
  cargo publish -p "$name" "${EXTRA_CARGO_ARGS[@]}" 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -e

  if (( rc == 0 )); then
    return 0
  fi

  if grep -qiE 'already exists on crates\.io|already uploaded' "$log"; then
    echo "==> ${name} ${VERSION} already on crates.io — treating as success"
    return 0
  fi

  if grep -qE '429|too many crates|rate limit|try again after' "$log"; then
    local wait
    if wait="$(secs_until_retry_after "$log")"; then
      wait_secs "$wait" "crates.io 429 for ${name}"
    else
      wait_secs "$(fallback_interval_for "$kind")" \
        "crates.io 429 for ${name} (no parseable retry time)"
    fi
    echo "==> retrying ${name}"
    cargo publish -p "$name" "${EXTRA_CARGO_ARGS[@]}"
    return $?
  fi

  echo "error: publish failed for ${name} (exit ${rc})" >&2
  return "$rc"
}

# Build the work list.
WORK=()
skipping=0
if [[ -n "$FROM" ]]; then
  skipping=1
fi

if [[ -n "$ONLY" ]]; then
  IFS=',' read -r -a only_list <<<"$ONLY"
  for name in "${only_list[@]}"; do
    name="$(echo "$name" | xargs)"
    found=0
    for c in "${CRATES[@]}"; do
      if [[ "$c" == "$name" ]]; then
        found=1
        break
      fi
    done
    if (( found == 0 )); then
      echo "error: unknown crate in --only: ${name}" >&2
      exit 2
    fi
    WORK+=("$name")
  done
else
  for name in "${CRATES[@]}"; do
    if (( skipping )); then
      if [[ "$name" == "$FROM" ]]; then
        skipping=0
      else
        echo "-- skip (before --from): ${name}"
        continue
      fi
    fi
    WORK+=("$name")
  done
  if (( skipping )); then
    echo "error: --from crate not in publish list: ${FROM}" >&2
    exit 2
  fi
fi

n=${#WORK[@]}
echo "Publishing ${n} crate(s) at version ${VERSION}"
echo "  interval-new=${INTERVAL_NEW_SECS}s  interval-update=${INTERVAL_UPDATE_SECS}s"
echo "  (0.1.0 on crates.io counts as historical — those publishes are updates)"
if (( DRY_RUN )); then
  echo "(dry run — no cargo publish)"
fi
echo

i=0
for name in "${WORK[@]}"; do
  i=$((i + 1))
  echo "---- [${i}/${n}] ${name} ----"

  if crate_version_published "$name" "$VERSION"; then
    echo "==> already published: ${name} ${VERSION} — skip"
    continue
  fi

  kind="new"
  if crate_exists "$name"; then
    kind="update"
    echo "==> existing crate (e.g. historical 0.1.0) → version update"
  else
    echo "==> brand-new crate name on crates.io"
  fi

  wait_for_bucket "$kind"

  if (( DRY_RUN )); then
    echo "==> would: cargo publish -p ${name}  [${kind}]"
    mark_bucket "$kind"
    echo
    continue
  fi

  publish_one "$name" "$kind"
  mark_bucket "$kind"
  echo
done

echo "Done. ${n} crate(s) processed for ${VERSION}."
