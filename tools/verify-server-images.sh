#!/usr/bin/env bash
# verify-server-images.sh — the gate between building and publishing the
# VorPilot Server images, run right before publishing so that what ships has
# been checked against the day's vulnerability data.
#
# Per image (Server Standard / Pro), against the expectations derived from the
# release tag:
#   - the platform set is exactly the one given, each with an SBOM;
#   - the version label is the publish tag;
#   - the version and the licensing endpoint are compiled into the image files
#     (release_checks.py inspect);
#   - Trivy finds no CRITICAL vulnerability that has a fix. Accepted exceptions
#     live in trivyignore.yaml, each with a statement. HIGH and CRITICAL are
#     written to trivy/<image>-<os>-<arch>.txt either way.
#
# The chart's third-party images (third-party-images.txt: the reverse proxy,
# the sign-in proxy, the init image) pass the same Trivy gate, pulled by digest
# from their registries for each platform: the hub runs them as much as its own,
# and a fixable CRITICAL in its sign-in proxy matters more than one in ours.
# Reports: trivy/third-party-<name>-<os>-<arch>.txt.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKS="$SCRIPT_DIR/release_checks.py"

usage() {
  echo "Usage: verify-server-images.sh --dir DIR --version X.Y.Z --tag TAG --platforms LIST --ignorefile FILE"
}

die() { echo "error: $*" >&2; exit 2; }

DIR="" VERSION="" TAG="" PLATFORMS="" IGNOREFILE=""
while [ "$#" -gt 0 ]; do
  case "$1" in -h|--help) usage; exit 0 ;; esac
  [ "$#" -ge 2 ] || { usage >&2; die "missing value for $1"; }
  case "$1" in
    --dir) DIR="$2" ;;
    --version) VERSION="$2" ;;
    --tag) TAG="$2" ;;
    --platforms) PLATFORMS="$2" ;;
    --ignorefile) IGNOREFILE="$2" ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift 2
done
for required in DIR VERSION TAG PLATFORMS IGNOREFILE; do
  [ -n "${!required}" ] || { usage >&2; die "missing --$(echo "$required" | tr 'A-Z' 'a-z')"; }
done
[ -d "$DIR" ] || die "$DIR not found"
[ -f "$IGNOREFILE" ] || die "$IGNOREFILE not found"
THIRD_PARTY="$DIR/third-party-images.txt"
grep -q '[^[:space:]]' "$THIRD_PARTY" 2>/dev/null || die "$THIRD_PARTY missing or empty"
command -v trivy >/dev/null 2>&1 || die "trivy not found"

COMPONENTS=(scout frontend)
failed=0
echo "Verifying images $TAG in $DIR"
for component in "${COMPONENTS[@]}"; do
  python3 "$CHECKS" inspect --component "$component" --layout "$DIR/$component" --tag "$TAG" \
    --version "$VERSION" --platforms "$PLATFORMS" || failed=1
done

mkdir -p "$DIR/trivy"
IFS=',' read -r -a PLATFORM_LIST <<<"$PLATFORMS"

# scan LABEL REPORT TRIVY_TARGET... — the report (HIGH and CRITICAL) and the gate
# (a fixable CRITICAL fails) for one image and platform.
scan() {
  local label="$1" report="$2"
  shift 2
  trivy image "$@" --quiet --scanners vuln \
    --severity HIGH,CRITICAL --ignorefile "$IGNOREFILE" --format table --output "$report"
  if trivy image "$@" --quiet --scanners vuln \
      --severity CRITICAL --ignore-unfixed --ignorefile "$IGNOREFILE" --exit-code 1 \
      --format table >"$report.gate" 2>&1; then
    echo "   ✓ $label — no fixable CRITICAL"
    rm -f "$report.gate"
  else
    echo "   ✗ $label — fixable CRITICAL vulnerabilities:"
    sed 's/^/      /' "$report.gate"
    failed=1
  fi
}

for component in "${COMPONENTS[@]}"; do
  for platform in "${PLATFORM_LIST[@]}"; do
    scan "$component $platform" "$DIR/trivy/$component-${platform//\//-}.txt" \
      --input "$DIR/$component" --platform "$platform"
  done
done

# --image-src remote: the registry's image for that platform, never a copy of
# the same tag in the local Docker daemon (another platform, or retagged).
while IFS= read -r reference || [ -n "$reference" ]; do
  [ -n "$reference" ] || continue
  case "$reference" in
    *@sha256:*) ;;
    *) echo "   ✗ $reference — not pinned by digest"; failed=1; continue ;;
  esac
  name="${reference%%@*}"; name="${name##*/}"; name="${name%%:*}"
  for platform in "${PLATFORM_LIST[@]}"; do
    scan "$name $platform" "$DIR/trivy/third-party-$name-${platform//\//-}.txt" \
      "$reference" --image-src remote --platform "$platform"
  done
done <"$THIRD_PARTY"

if [ "$failed" -ne 0 ]; then
  echo "Verification failed — nothing may be published from $DIR." >&2
  exit 1
fi
echo "Verification passed."
