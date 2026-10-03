#!/usr/bin/env bash
# prepare-release.sh — everything the release workflow does before publishing;
# shared by the release job and the manual rehearsal, which stops here.
#
#   1. download the assets of the release tagged --tag (normally still a draft,
#      visible only with write access) into <work>/artifacts;
#   2. check them: checksums, release.json against the tag, version and
#      endpoint inside the binaries and the web UI bundle;
#   3. build the images into <work>/server (build-server-images.sh);
#   4. check the images (verify-server-images.sh).
#
# The tag names everything: v<version> → release channel, v<version>-beta →
# beta. Needs gh (GH_TOKEN), docker buildx, trivy and python3.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKS="$SCRIPT_DIR/release_checks.py"

usage() {
  echo "Usage: prepare-release.sh --repo OWNER/NAME --tag vX.Y.Z[-beta] --revision SHA --work DIR --docker-dir DIR --ignorefile FILE"
}

die() { echo "error: $*" >&2; exit 2; }

REPO="" TAG="" REVISION="" WORK="" DOCKER_DIR="" IGNOREFILE=""
while [ "$#" -gt 0 ]; do
  case "$1" in -h|--help) usage; exit 0 ;; esac
  [ "$#" -ge 2 ] || { usage >&2; die "missing value for $1"; }
  case "$1" in
    --repo) REPO="$2" ;;
    --tag) TAG="$2" ;;
    --revision) REVISION="$2" ;;
    --work) WORK="$2" ;;
    --docker-dir) DOCKER_DIR="$2" ;;
    --ignorefile) IGNOREFILE="$2" ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift 2
done
for required in REPO TAG REVISION WORK DOCKER_DIR IGNOREFILE; do
  [ -n "${!required}" ] || { usage >&2; die "missing --$(echo "$required" | tr 'A-Z_' 'a-z-')"; }
done
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "tag $TAG is not v<major>.<minor>.<patch>[-beta]" ;; esac
IMAGE_TAG="${TAG#v}"
VERSION="${IMAGE_TAG%%-*}"

ARTIFACTS="$WORK/artifacts"
rm -rf "$WORK"
mkdir -p "$ARTIFACTS"

release_ids="$(gh api "repos/$REPO/releases?per_page=100" --paginate \
  --jq ".[] | select(.tag_name == \"$TAG\") | .id")"
[ "$(printf '%s' "$release_ids" | grep -c .)" = 1 ] \
  || die "expected one release tagged $TAG in $REPO, found: ${release_ids:-none}"
echo "Release $TAG (id $release_ids): downloading assets"
gh api "repos/$REPO/releases/$release_ids" --jq '.assets[] | "\(.id) \(.name)"' >"$WORK/assets.txt"
while read -r asset_id name; do
  # Asset names become file names here: allow nothing but plain names.
  case "$name" in *[!A-Za-z0-9._-]*|.*) die "unexpected asset name: $name" ;; esac
  gh api -H "Accept: application/octet-stream" "repos/$REPO/releases/assets/$asset_id" >"$ARTIFACTS/$name"
done <"$WORK/assets.txt"

python3 "$CHECKS" check-artifacts --dir "$ARTIFACTS" --tag "$IMAGE_TAG" --version "$VERSION"

bash "$SCRIPT_DIR/build-server-images.sh" --artifacts "$ARTIFACTS" --out "$WORK/server" \
  --tag "$IMAGE_TAG" --docker-dir "$DOCKER_DIR" \
  --source-url "https://github.com/$REPO" --revision "$REVISION"

PLATFORMS="$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["platforms"]))' "$WORK/server/release.json")"
bash "$SCRIPT_DIR/verify-server-images.sh" --dir "$WORK/server" --version "$VERSION" --tag "$IMAGE_TAG" \
  --platforms "$PLATFORMS" --ignorefile "$IGNOREFILE"
