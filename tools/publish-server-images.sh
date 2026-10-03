#!/usr/bin/env bash
# publish-server-images.sh — ships the checked VorPilot Server image layouts.
# Runs in the release job after verify-server-images.sh, with the job token
# logged in to the registry and an OIDC token available for keyless signing.
#
# Nothing is rebuilt, so the registry digest is the digest that was checked.
# Per image:
#   1. refuse unless publishable (release_checks.py check-publishable): a
#      release or beta tag, layouts unchanged since they were recorded;
#   2. tags are immutable: same digest already there → skip the copy (a re-run
#      after a failed signature), another digest → refuse. Only a registry
#      answer of "no such tag" counts as absent; any other error stops the run
#      instead of risking an overwrite;
#   3. copy with regctl and re-read the remote digest;
#   4. sign the digest keyless (--recursive: the index and every platform
#      manifest), then verify it against this workflow's identity;
#   5. release channel only: move `latest` to this version unless a newer
#      version already holds it — latest never moves back, beta never touches it.
# Writes images.txt (these images and the Helm chart's third-party images, by
# digest) and digests.env (SCOUT_DIGEST=…, FRONTEND_DIGEST=…) for attestation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKS="$SCRIPT_DIR/release_checks.py"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

usage() {
  echo "Usage: publish-server-images.sh --dir DIR --tag TAG --registry HOST/NAMESPACE --identity URL"
}

die() { echo "error: $*" >&2; exit 2; }

DIR="" TAG="" REGISTRY="" IDENTITY=""
while [ "$#" -gt 0 ]; do
  case "$1" in -h|--help) usage; exit 0 ;; esac
  [ "$#" -ge 2 ] || { usage >&2; die "missing value for $1"; }
  case "$1" in
    --dir) DIR="$2" ;;
    --tag) TAG="$2" ;;
    --registry) REGISTRY="$2" ;;
    --identity) IDENTITY="$2" ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift 2
done
for required in DIR TAG REGISTRY IDENTITY; do
  [ -n "${!required}" ] || { usage >&2; die "missing --$(echo "$required" | tr 'A-Z' 'a-z')"; }
done
for tool in regctl cosign python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
done

ROWS="$(python3 "$CHECKS" check-publishable --dir "$DIR" --tag "$TAG")" || exit 1
[ -f "$DIR/third-party-images.txt" ] || die "$DIR/third-party-images.txt missing"
CHANNEL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["channel"])' "$DIR/release.json")"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vorpilot-publish.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM

rc() { regctl --verbosity error "$@"; }

# Prints the digest, or nothing when the registry says the tag does not exist.
# Runs in a command substitution, where die only ends the subshell — every
# caller must `|| exit` on it, or an unclear answer would read as "absent".
# stdout and stderr stay apart: only stdout is a digest.
remote_digest() {
  local output error
  if output="$(rc image digest "$1" 2>"$TMP_ROOT/digest.err")"; then
    printf '%s\n' "$output"
    return 0
  fi
  error="$(cat "$TMP_ROOT/digest.err")"
  case "$error" in
    *"not found"*|*"manifest unknown"*|*MANIFEST_UNKNOWN*|*"name unknown"*|*NAME_UNKNOWN*) return 0 ;;
  esac
  die "cannot tell whether $1 exists, refusing to push: $error"
}

cosign_verify() {
  cosign verify --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$1" >"$TMP_ROOT/verify.out" 2>&1
}

# Version recorded on whatever `latest` holds now (index annotation), or nothing
# when there is no `latest` yet. Same contract as remote_digest: an unclear
# answer stops the run — guessing "unset" could move latest backwards.
latest_version() {
  local held version
  held="$(remote_digest "$1")" || return 2
  [ -n "$held" ] || return 0
  version="$(rc manifest get "$1" --format '{{index .Annotations "org.opencontainers.image.version"}}')" || return 2
  case "$version" in
    [0-9]*.[0-9]*.[0-9]*) printf '%s\n' "$version" ;;
    *) echo "error: $1 carries no readable version annotation (${version:-empty}); move latest by hand" >&2; return 2 ;;
  esac
}

: >"$TMP_ROOT/images.txt"
: >"$TMP_ROOT/digests.env"
while read -r component name digest; do
  reference="$REGISTRY/$name:$TAG"
  pinned="$REGISTRY/$name@$digest"
  existing="$(remote_digest "$reference")" || exit 2
  if [ "$existing" = "$digest" ]; then
    echo "   = $reference already holds $digest"
  elif [ -n "$existing" ]; then
    die "$reference already holds $existing, this build is $digest — a published version is never overwritten"
  else
    rc image copy "ocidir://$DIR/$component:$TAG" "$reference" </dev/null >/dev/null
    copied="$(remote_digest "$reference")" || exit 2
    [ "$copied" = "$digest" ] || die "$reference reads back as ${copied:-nothing}, expected $digest"
    echo "   ↑ $reference  $digest"
  fi

  if cosign_verify "$pinned" </dev/null; then
    echo "   = $pinned already signed by this workflow"
  else
    cosign sign --yes --recursive "$pinned" </dev/null
    cosign_verify "$pinned" </dev/null || { cat "$TMP_ROOT/verify.out" >&2; die "signature on $pinned does not verify"; }
    echo "   ✓ $pinned signed and verified"
  fi

  if [ "$CHANNEL" = release ]; then
    current="$(latest_version "$REGISTRY/$name:latest")" || exit 2
    newest="$(printf '%s\n%s\n' "$current" "$TAG" | sed '/^$/d' | sort -V | tail -1)"
    if [ "$newest" = "$TAG" ] && [ "$current" != "$TAG" ]; then
      rc image copy "$pinned" "$REGISTRY/$name:latest" </dev/null >/dev/null
      echo "   → $REGISTRY/$name:latest now $TAG (was ${current:-unset})"
    else
      echo "   = $REGISTRY/$name:latest stays ${current} (not older than $TAG)"
    fi
  fi

  echo "$reference@$digest" >>"$TMP_ROOT/images.txt"
  echo "$(echo "$component" | tr 'a-z' 'A-Z')_DIGEST=$digest" >>"$TMP_ROOT/digests.env"
done <<<"$ROWS"

cat "$DIR/third-party-images.txt" >>"$TMP_ROOT/images.txt"
cp "$TMP_ROOT/images.txt" "$DIR/images.txt"
cp "$TMP_ROOT/digests.env" "$DIR/digests.env"
echo ""
echo "Published $TAG. Pinned references:"
sed 's/^/   /' "$DIR/images.txt"
