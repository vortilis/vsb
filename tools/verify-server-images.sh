#!/usr/bin/env bash
# verify-server-images.sh — the gate between building and publishing the
# VorPilot Server images, run right before publishing so that what ships has
# been checked against the day's vulnerability data.
#
# Per image, against the expectations derived from the release tag:
#   - the platform set is exactly the one given, each with an SBOM;
#   - the version label is the publish tag;
#   - the version and the service endpoint are compiled into the image files
#     (release_checks.py inspect);
#   - Trivy finds no CRITICAL vulnerability that has a fix. Accepted exceptions
#     live in trivyignore.yaml, each with a statement. HIGH and CRITICAL are
#     written to trivy/<image>-<os>-<arch>.txt either way.
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
command -v trivy >/dev/null 2>&1 || die "trivy not found"

failed=0
echo "Verifying images $TAG in $DIR"
for component in scout frontend; do
  python3 "$CHECKS" inspect --component "$component" --layout "$DIR/$component" --tag "$TAG" \
    --version "$VERSION" --platforms "$PLATFORMS" || failed=1
done

mkdir -p "$DIR/trivy"
IFS=',' read -r -a PLATFORM_LIST <<<"$PLATFORMS"
for component in scout frontend; do
  for platform in "${PLATFORM_LIST[@]}"; do
    report="$DIR/trivy/$component-${platform//\//-}.txt"
    trivy image --input "$DIR/$component" --platform "$platform" --quiet --scanners vuln \
      --severity HIGH,CRITICAL --ignorefile "$IGNOREFILE" --format table --output "$report"
    if trivy image --input "$DIR/$component" --platform "$platform" --quiet --scanners vuln \
        --severity CRITICAL --ignore-unfixed --ignorefile "$IGNOREFILE" --exit-code 1 \
        --format table >"$report.gate" 2>&1; then
      echo "   ✓ $component $platform — no fixable CRITICAL"
      rm -f "$report.gate"
    else
      echo "   ✗ $component $platform — fixable CRITICAL vulnerabilities:"
      sed 's/^/      /' "$report.gate"
      failed=1
    fi
  done
done

if [ "$failed" -ne 0 ]; then
  echo "Verification failed — nothing may be published from $DIR." >&2
  exit 1
fi
echo "Verification passed."
