#!/usr/bin/env python3
"""Checks for VorPilot Server release builds.

A release starts as a set of pre-built artifacts, described by release.json and
listed in checksums.txt. The release workflow checks them, builds the images
into OCI image layouts, checks the images and publishes exactly those layouts.
Everything is read with the standard library, straight from the files:

  check-artifacts    checksums, release.json against the tag, and the version
                     and service endpoint compiled into the binaries and the
                     web UI bundle
  digest             index digest of a tag in an OCI layout
  inspect            one image layout: platform set, SBOM per platform,
                     version label, version and endpoint inside the files
  record-images      add the digests of the built layouts to release.json
  check-publishable  tag and channel rules, layouts unchanged since recorded;
                     prints "<component> <name> <digest>" per image
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
import tarfile
from pathlib import Path

REF_NAME = "org.opencontainers.image.ref.name"
VERSION_LABEL = "org.opencontainers.image.version"
SPDX_PREDICATE = "https://spdx.dev/Document"

# Every published build talks to these endpoints; a build that lacks them was
# made for something else.
PRODUCTION_MARKERS = {
    "scout": "https://api.vortilis.com/license",
    "frontend": "https://lic.vortilis.com",
}

# Files whose bytes must hold the version and the endpoint, as paths inside the
# image without the leading slash. Bundle chunks are content-hashed, so they are
# matched by pattern and searched together.
COMPONENT_FILES = {
    "scout": "usr/local/bin/scout",
    "frontend": "usr/share/nginx/html/assets/*.js",
}

# Artifact names are flat: they travel as release assets.
FRONTEND_BUNDLE = "frontend-dist.tar.gz"
BUNDLE_CHUNKS = "dist-web/assets/*.js"
RECORD = "release.json"
CHECKSUMS = "checksums.txt"
THIRD_PARTY = "third-party-images.txt"
PUBLISHED_CHANNELS = ("release", "beta")


class CheckError(Exception):
    """A check failed; the message is what the operator needs to read."""


def scout_binary(platform: str) -> str:
    return "scout-" + platform.replace("/", "-")


def artifact_names(platforms: list[str]) -> list[str]:
    """Every artifact of a release besides checksums.txt itself."""
    return sorted([scout_binary(p) for p in platforms] + [FRONTEND_BUNDLE, RECORD, THIRD_PARTY])


def channel_of(tag: str) -> str:
    """X.Y.Z → release, X.Y.Z-<suffix> → <suffix>."""
    return tag.split("-", 1)[1] if "-" in tag else "release"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def checksum_failures(directory: Path, expected: list[str]) -> list[str]:
    """checksums.txt lists exactly the expected files, and they match it."""
    path = directory / CHECKSUMS
    if not path.is_file():
        return [f"{path} missing"]
    listed = {}
    for line in path.read_text().splitlines():
        digest, _, name = line.partition("  ")
        listed[name] = digest
    failures = []
    if sorted(listed) != sorted(expected):
        failures.append(f"checksums.txt lists {sorted(listed)}, expected {sorted(expected)}")
    for name in expected:
        file = directory / name
        if not file.is_file():
            failures.append(f"{name} missing")
        elif name in listed and sha256_file(file) != listed[name]:
            failures.append(f"{name} does not match checksums.txt")
    return failures


def content_failures(where: str, content: bytes, version: str, expected: str,
                     forbidden: tuple[str, ...] = ()) -> list[str]:
    failures = []
    # One-directional: a build of another version does not contain this
    # version's string.
    if version.encode() not in content:
        failures.append(f"{where}: version {version} not found")
    if expected.encode() not in content:
        failures.append(f"{where}: endpoint {expected} not found")
    for marker in forbidden:
        if marker.encode() in content:
            failures.append(f"{where}: unexpected endpoint {marker} compiled in")
    return failures


def bundle_chunks(bundle: Path) -> bytes:
    chunks = []
    with tarfile.open(bundle, mode="r:*") as archive:
        for member in archive:
            if member.isfile() and fnmatch.fnmatchcase(member.name.removeprefix("./"), BUNDLE_CHUNKS):
                extracted = archive.extractfile(member)
                chunks.append(extracted.read() if extracted else b"")
    return b"\0".join(chunks)


def artifact_content_failures(directory: Path, platforms: list[str], version: str,
                              markers: dict, forbidden: dict | None = None) -> list[str]:
    """Version and endpoint inside every binary and the bundle."""
    forbidden = forbidden or {}
    failures = []
    for platform in platforms:
        name = scout_binary(platform)
        failures += content_failures(name, (directory / name).read_bytes(), version,
                                     markers["scout"], forbidden.get("scout", ()))
    chunks = bundle_chunks(directory / FRONTEND_BUNDLE)
    if not chunks:
        failures.append(f"{FRONTEND_BUNDLE}: no files match {BUNDLE_CHUNKS}")
    else:
        failures += content_failures(FRONTEND_BUNDLE, chunks, version,
                                     markers["frontend"], forbidden.get("frontend", ()))
    return failures


def load_record(directory: Path) -> dict:
    path = directory / RECORD
    if not path.is_file():
        raise CheckError(f"{path} missing")
    return json.loads(path.read_text())


def tag_failures(record: dict, tag: str) -> list[str]:
    """Why a recorded build must not be published under tag (empty = may)."""
    failures = []
    if record["tag"] != tag:
        failures.append(f"built as {record['tag']}, not {tag}")
    if channel_of(tag) not in PUBLISHED_CHANNELS:
        failures.append(f"{tag} is not a release or beta tag")
    elif record["channel"] != channel_of(tag):
        failures.append(f"recorded channel {record['channel']} does not match {tag}")
    return failures


def check_artifacts(directory: Path, tag: str, version: str) -> list[str]:
    record = load_record(directory)
    failures = tag_failures(record, tag)
    if record["version"] != version:
        failures.append(f"release.json says version {record['version']}, expected {version}")
    failures += checksum_failures(directory, artifact_names(record["platforms"]))
    if failures:
        return failures  # contents of a mismatched set prove nothing
    return artifact_content_failures(directory, record["platforms"], version, PRODUCTION_MARKERS)


# ---- image layouts ----------------------------------------------------------------

class Layout:
    """Read-only view of an OCI image layout directory."""

    def __init__(self, root: Path):
        self.root = root
        if not (root / "index.json").is_file():
            raise CheckError(f"{root}: not an OCI image layout (no index.json)")

    def blob_path(self, digest: str) -> Path:
        algorithm, _, encoded = digest.partition(":")
        return self.root / "blobs" / algorithm / encoded

    def json_blob(self, digest: str) -> dict:
        return json.loads(self.blob_path(digest).read_text())

    def tag_descriptor(self, tag: str) -> dict:
        index = json.loads((self.root / "index.json").read_text())
        matches = [m for m in index.get("manifests", [])
                   if m.get("annotations", {}).get(REF_NAME) == tag]
        if len(matches) != 1:
            raise CheckError(f"{self.root}: expected one entry tagged {tag}, found {len(matches)}")
        return matches[0]

    def image_index(self, tag: str) -> dict:
        # buildx always writes an index once attestations are on, even for one
        # platform; a bare manifest here means the SBOM was never produced.
        descriptor = self.tag_descriptor(tag)
        if not descriptor.get("mediaType", "").endswith("image.index.v1+json"):
            raise CheckError(f"{self.root}:{tag} is not an image index — built without attestations?")
        return self.json_blob(descriptor["digest"])


def platform_name(descriptor: dict) -> str:
    platform = descriptor.get("platform", {})
    parts = [platform.get("os", ""), platform.get("architecture", "")]
    if platform.get("variant"):
        parts.append(platform["variant"])
    return "/".join(parts)


def image_manifests(index: dict) -> dict[str, dict]:
    """Platform → manifest descriptor; attestation manifests (unknown/unknown) excluded."""
    return {platform_name(m): m for m in index.get("manifests", [])
            if m.get("platform", {}).get("os") != "unknown"}


def has_sbom(layout: Layout, index: dict, manifest_digest: str) -> bool:
    for descriptor in index.get("manifests", []):
        annotations = descriptor.get("annotations", {})
        if (annotations.get("vnd.docker.reference.type") == "attestation-manifest"
                and annotations.get("vnd.docker.reference.digest") == manifest_digest):
            attestation = layout.json_blob(descriptor["digest"])
            return any(layer.get("annotations", {}).get("in-toto.io/predicate-type") == SPDX_PREDICATE
                       for layer in attestation.get("layers", []))
    return False


def _member_path(name: str) -> str:
    while name.startswith("./") or name.startswith("/"):
        name = name[1:] if name.startswith("/") else name[2:]
    return name


def read_files(layout: Layout, manifest_digest: str, pattern: str) -> dict[str, bytes]:
    """Contents of the files matching pattern as the image presents them: a file
    in a later layer replaces the same path from an earlier one."""
    manifest = layout.json_blob(manifest_digest)
    files: dict[str, bytes] = {}
    for layer in manifest.get("layers", []):
        with tarfile.open(layout.blob_path(layer["digest"]), mode="r:*") as archive:
            for member in archive:
                path = _member_path(member.name)
                if member.isfile() and fnmatch.fnmatchcase(path, pattern):
                    extracted = archive.extractfile(member)
                    files[path] = extracted.read() if extracted else b""
    return files


def image_labels(layout: Layout, manifest_digest: str) -> dict:
    manifest = layout.json_blob(manifest_digest)
    config = layout.json_blob(manifest["config"]["digest"])
    return config.get("config", {}).get("Labels") or {}


def inspect(component: str, layout: Layout, tag: str, version: str, platforms: list[str]) -> list[str]:
    """Every check for one image; returns failure messages (empty = all good)."""
    index = layout.image_index(tag)
    manifests = image_manifests(index)
    failures = []
    if sorted(manifests) != sorted(platforms):
        failures.append(f"{component}: platforms {sorted(manifests)}, expected {sorted(platforms)}")
    for platform in sorted(set(manifests) & set(platforms)):
        digest = manifests[platform]["digest"]
        where = f"{component} {platform}"
        if not has_sbom(layout, index, digest):
            failures.append(f"{where}: no SBOM attestation")
        label = image_labels(layout, digest).get(VERSION_LABEL)
        if label != tag:
            failures.append(f"{where}: label {VERSION_LABEL}={label!r}, expected {tag!r}")
        files = read_files(layout, digest, COMPONENT_FILES[component])
        if not files:
            failures.append(f"{where}: no files match {COMPONENT_FILES[component]}")
            continue
        failures += content_failures(where, b"\0".join(files.values()), version, PRODUCTION_MARKERS[component])
    return failures


def record_images(directory: Path, tag: str, specs: list[str]) -> None:
    record = load_record(directory)
    images = {}
    for spec in specs:
        component, name, layout_dir = spec.split("=", 2)
        images[component] = {
            "name": name,
            "layout": str(Path(layout_dir).resolve().relative_to(directory.resolve())),
            "digest": Layout(Path(layout_dir)).tag_descriptor(tag)["digest"],
        }
    record["images"] = images
    (directory / RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def check_publishable(directory: Path, tag: str) -> list[tuple[str, str, str]]:
    record = load_record(directory)
    failures = tag_failures(record, tag)
    if failures:
        raise CheckError("; ".join(failures))
    if not record.get("images"):
        raise CheckError(f"{directory / RECORD} records no images — build them first")
    rows = []
    for component, image in sorted(record["images"].items()):
        current = Layout(directory / image["layout"]).tag_descriptor(tag)["digest"]
        if current != image["digest"]:
            raise CheckError(f"{component}: layout is {current}, release.json recorded {image['digest']}")
        rows.append((component, image["name"], current))
    return rows


# ---- command line -----------------------------------------------------------------

def report(failures: list[str], success: str) -> int:
    for failure in failures:
        print(f"   ✗ {failure}")
    if failures:
        return 1
    print(f"   ✓ {success}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    artifacts = sub.add_parser("check-artifacts")
    for option in ("--dir", "--tag", "--version"):
        artifacts.add_argument(option, required=True)

    digest = sub.add_parser("digest")
    digest.add_argument("--layout", required=True)
    digest.add_argument("--tag", required=True)

    check = sub.add_parser("inspect")
    check.add_argument("--component", required=True, choices=sorted(PRODUCTION_MARKERS))
    for option in ("--layout", "--tag", "--version", "--platforms"):
        check.add_argument(option, required=True)

    images = sub.add_parser("record-images")
    images.add_argument("--dir", required=True)
    images.add_argument("--tag", required=True)
    images.add_argument("--image", action="append", required=True, help="component=name=layout-dir, repeated")

    publishable = sub.add_parser("check-publishable")
    publishable.add_argument("--dir", required=True)
    publishable.add_argument("--tag", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "check-artifacts":
            failures = check_artifacts(Path(args.dir), args.tag, args.version)
            return report(failures, f"artifacts {args.tag} — checksums, version {args.version}, endpoints")
        if args.command == "digest":
            print(Layout(Path(args.layout)).tag_descriptor(args.tag)["digest"])
        elif args.command == "inspect":
            failures = inspect(args.component, Layout(Path(args.layout)), args.tag, args.version,
                               args.platforms.split(","))
            return report(failures, f"{args.component} — {args.platforms}, version {args.version}, "
                                    "endpoint, SBOM")
        elif args.command == "record-images":
            record_images(Path(args.dir), args.tag, args.image)
        elif args.command == "check-publishable":
            for row in check_publishable(Path(args.dir), args.tag):
                print(" ".join(row))
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
