#!/usr/bin/env bash
# verify-server-charts.sh — checks the release's Helm charts. Runs after the
# images are built and checked (prepare-release.sh), so a rehearsal covers it
# too. A chart of version X runs the images tagged X; the packages are
# published exactly as they arrived.
#
# For each chart package of the release:
#   1. name, version and appVersion are the release tag — bundled subcharts too;
#   2. helm lint, then helm template with default values: the release's own
#      images render as exactly <registry>/<name>:<tag>.
# Copies the checked packages to <dir>/charts/ for publish-server-release.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKS="$SCRIPT_DIR/release_checks.py"
CHARTS=(vorpilot-server vorpilot-agent vorpilot-rbac-bootstrap)

usage() {
  echo "Usage: verify-server-charts.sh --artifacts DIR --dir DIR --tag TAG --registry HOST/NAMESPACE"
}

die() { echo "error: $*" >&2; exit 2; }

ARTIFACTS="" DIR="" TAG="" REGISTRY=""
while [ "$#" -gt 0 ]; do
  case "$1" in -h|--help) usage; exit 0 ;; esac
  [ "$#" -ge 2 ] || { usage >&2; die "missing value for $1"; }
  case "$1" in
    --artifacts) ARTIFACTS="$2" ;;
    --dir) DIR="$2" ;;
    --tag) TAG="$2" ;;
    --registry) REGISTRY="$2" ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift 2
done
for required in ARTIFACTS DIR TAG REGISTRY; do
  [ -n "${!required}" ] || { usage >&2; die "missing --$(echo "$required" | tr 'A-Z' 'a-z')"; }
done
command -v helm >/dev/null 2>&1 || die "helm not found"

# The agent chart refuses to render without the hub's endpoints and agent CA;
# placeholders are enough to see every image it would run.
CA="$(printf '%s\n' '-----BEGIN CERTIFICATE-----' 'MIIB' '-----END CERTIFICATE-----' | base64 | tr -d '\n')"
AGENT_VALUES=(--set-string gateway.host=control.example.com --set-string gateway.tunnelHost=tunnel.example.com
              --set-string "gateway.caBundleBase64=$CA" --set-string enrollment.token=example)

mkdir -p "$DIR/charts"
failed=0
for chart in "${CHARTS[@]}"; do
  package="$chart-$TAG.tgz"
  python3 "$CHECKS" check-chart --chart "$ARTIFACTS/$package" --name "$chart" --tag "$TAG" || exit 1
  case "$chart" in
    vorpilot-server)
      expect=(--image "$REGISTRY/vorpilot-scout" --image "$REGISTRY/vorpilot-frontend")
      values=() ;;
    vorpilot-agent)
      expect=(--image "$REGISTRY/vorpilot-scout")
      values=("${AGENT_VALUES[@]}") ;;
    *)
      expect=() values=() ;;
  esac
  cp "$ARTIFACTS/$package" "$DIR/charts/$package"
  helm lint "$DIR/charts/$package" ${values[@]+"${values[@]}"} >"$DIR/charts/$chart.lint" 2>&1 \
    || { sed 's/^/      /' "$DIR/charts/$chart.lint"; die "helm lint failed for $package"; }
  helm template "$chart" "$DIR/charts/$package" ${values[@]+"${values[@]}"} >"$DIR/charts/$chart.yaml"
  python3 "$CHECKS" check-rendered --manifest "$DIR/charts/$chart.yaml" --tag "$TAG" ${expect[@]+"${expect[@]}"} \
    || failed=1
done
[ "$failed" -eq 0 ] || { echo "Chart checks failed — nothing is published." >&2; exit 1; }
echo "Charts $TAG checked."
