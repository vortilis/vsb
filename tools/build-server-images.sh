#!/usr/bin/env bash
# build-server-images.sh — builds the VorPilot Server images from checked
# release artifacts.
#
# Builds vorpilot-scout and vorpilot-frontend for the platforms in release.json,
# each into an OCI image layout under --out with an SBOM and minimal provenance,
# and records their digests in --out/release.json. Nothing is pushed:
# verify-server-images.sh looks inside these layouts, publish-server-images.sh
# ships exactly them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKS="$SCRIPT_DIR/release_checks.py"

usage() {
  cat <<'EOF'
Usage: build-server-images.sh --artifacts DIR --out DIR --tag TAG --docker-dir DIR
         --source-url URL --revision SHA [--image-prefix vorpilot-]
EOF
}

die() { echo "error: $*" >&2; exit 2; }

ARTIFACTS="" OUT="" TAG="" DOCKER_DIR="" SOURCE_URL="" REVISION="" IMAGE_PREFIX="vorpilot-"
while [ "$#" -gt 0 ]; do
  case "$1" in -h|--help) usage; exit 0 ;; esac
  [ "$#" -ge 2 ] || { usage >&2; die "missing value for $1"; }
  case "$1" in
    --artifacts) ARTIFACTS="$2" ;;
    --out) OUT="$2" ;;
    --tag) TAG="$2" ;;
    --docker-dir) DOCKER_DIR="$2" ;;
    --source-url) SOURCE_URL="$2" ;;
    --revision) REVISION="$2" ;;
    --image-prefix) IMAGE_PREFIX="$2" ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift 2
done
for required in ARTIFACTS OUT TAG DOCKER_DIR SOURCE_URL REVISION; do
  [ -n "${!required}" ] || { usage >&2; die "missing --$(echo "$required" | tr 'A-Z_' 'a-z-')"; }
done
[ -f "$ARTIFACTS/release.json" ] || die "$ARTIFACTS/release.json missing"
command -v docker >/dev/null 2>&1 || die "docker not found"

record() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]
print(",".join(v) if isinstance(v, list) else v)' "$ARTIFACTS/release.json" "$1"; }
PLATFORMS="$(record platforms)"
[ "$(record tag)" = "$TAG" ] || die "artifacts were built as $(record tag), not $TAG"

rm -rf "$OUT"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cp "$ARTIFACTS/release.json" "$ARTIFACTS/third-party-images.txt" "$OUT/"

CONTEXT="$(mktemp -d "${TMPDIR:-/tmp}/vorpilot-images.XXXXXX")"
trap 'rm -rf "$CONTEXT"' EXIT INT TERM

# Labels land in each platform's config (what `docker inspect` shows); index
# annotations are what GHCR reads for a multi-platform package page.
metadata_args() {
  local name="$1" description="$2" pair
  METADATA=()
  for pair in \
    "org.opencontainers.image.title=$name" \
    "org.opencontainers.image.description=$description" \
    "org.opencontainers.image.version=$TAG" \
    "org.opencontainers.image.revision=$REVISION" \
    "org.opencontainers.image.source=$SOURCE_URL" \
    "org.opencontainers.image.url=https://vortilis.com" \
    "org.opencontainers.image.vendor=Vortilis"; do
    METADATA+=(--label "$pair" --annotation "index:$pair")
  done
}

# The layout's own name is registry-neutral: the registry is chosen at publish.
build_layout() {
  local component="$1" dockerfile="$2" context="$3"
  docker buildx build --platform "$PLATFORMS" -f "$dockerfile" "${METADATA[@]}" \
    --sbom=true --provenance=mode=min \
    --output "type=oci,dest=$OUT/$component,tar=false,name=$IMAGE_PREFIX$component:$TAG" \
    "$context"
}

mkdir -p "$CONTEXT/scout" "$CONTEXT/frontend"
IFS=',' read -r -a PLATFORM_LIST <<<"$PLATFORMS"
for platform in "${PLATFORM_LIST[@]}"; do
  cp "$ARTIFACTS/scout-${platform//\//-}" "$CONTEXT/scout/"
done
cp "$DOCKER_DIR/Dockerfile.scout" "$CONTEXT/scout/"
metadata_args "${IMAGE_PREFIX}scout" "VorPilot Server backend"
build_layout scout "$CONTEXT/scout/Dockerfile.scout" "$CONTEXT/scout"

tar -xzf "$ARTIFACTS/frontend-dist.tar.gz" -C "$CONTEXT/frontend"
mv "$CONTEXT/frontend/dist-web" "$CONTEXT/frontend/dist"
cp "$DOCKER_DIR/Dockerfile.frontend" "$DOCKER_DIR/nginx.conf" "$CONTEXT/frontend/"
metadata_args "${IMAGE_PREFIX}frontend" "VorPilot Server web UI"
build_layout frontend "$CONTEXT/frontend/Dockerfile.frontend" "$CONTEXT/frontend"

python3 "$CHECKS" record-images --dir "$OUT" --tag "$TAG" \
  --image "scout=${IMAGE_PREFIX}scout=$OUT/scout" \
  --image "frontend=${IMAGE_PREFIX}frontend=$OUT/frontend"

echo "Built $TAG for $PLATFORMS:"
for component in scout frontend; do
  echo "   $IMAGE_PREFIX$component  $(python3 "$CHECKS" digest --layout "$OUT/$component" --tag "$TAG")"
done
