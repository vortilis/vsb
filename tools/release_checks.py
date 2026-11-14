#!/usr/bin/env python3
"""Checks for VorPilot Server release builds.

A release starts as a set of pre-built artifacts, described by release.json and
listed in checksums.txt: binaries, the web UI bundles and the Helm chart
packages. The release workflow checks them, builds the images into OCI image
layouts, checks the images and the charts, and publishes exactly those layouts
and packages. A chart of version X runs the images tagged X. Everything is
read with the standard library, straight from the files.

Two editions ship from one release: Server Standard / Pro (scout, frontend)
and Server CE (scout-ce, frontend-ce), the open-source build. The CE images
talk to no licensing service, so they must carry none of its endpoints; the CE
Scout keeps its Go build info, which names its main package.

  check-artifacts    checksums, release.json against the tag, the version and
                     the markers compiled into the binaries and the web UI
                     bundles, and the chart packages' names and versions
  digest             index digest of a tag in an OCI layout
  inspect            one image layout: platform set, SBOM per platform,
                     version label, version and markers inside the files
  record-images      add the digests of the built layouts to release.json
  check-publishable  tag and channel rules, layouts unchanged since recorded;
                     prints "<component> <name> <digest>" per image
  check-chart        one chart package: name, version and appVersion of the
                     chart and of every bundled subchart
  yaml-set           set scalars in a YAML file in place, keeping its comments
  check-rendered     the release's own images in a rendered chart are exactly
                     <repository>:<tag>, and the absent ones are absent
  file-digest        sha256 of a file, as a registry names a layer
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

REF_NAME = "org.opencontainers.image.ref.name"
VERSION_LABEL = "org.opencontainers.image.version"
SPDX_PREDICATE = "https://spdx.dev/Document"

# Every published Server Standard / Pro build talks to these endpoints; a build
# that lacks them was made for something else.
PRODUCTION_MARKERS = {
    "scout": "https://api.vortilis.com/license",
    "frontend": "https://lic.vortilis.com",
}

# The Server CE Scout's Go build info names its main package: the open-source
# command, not another binary under its name.
CE_SCOUT_PATH = "path\tvortilis.com/vorpilot/cmd/scout\n"

# Image components: the Scout binaries, then the web UI bundles.
SCOUTS = ("scout", "scout-ce")
BUNDLES = {"frontend": "frontend-dist.tar.gz", "frontend-ce": "frontend-ce-dist.tar.gz"}
COMPONENTS = SCOUTS + tuple(BUNDLES)

# Files whose bytes must hold the version and the markers, as paths inside the
# image without the leading slash. Bundle chunks are content-hashed, so they are
# matched by pattern and searched together.
COMPONENT_FILES = {
    "scout": "usr/local/bin/scout",
    "scout-ce": "usr/local/bin/scout",
    "frontend": "usr/share/nginx/html/assets/*.js",
    "frontend-ce": "usr/share/nginx/html/assets/*.js",
}

# Artifact names are flat: they travel as release assets.
BUNDLE_CHUNKS = "dist-web/assets/*.js"
RECORD = "release.json"
CHECKSUMS = "checksums.txt"
THIRD_PARTY = "third-party-images.txt"
PUBLISHED_CHANNELS = ("release",)
# Published as oci://<registry>/charts/<name>, versioned with the release tag.
CHARTS = ("vorpilot-server", "vorpilot-agent", "vorpilot-rbac-bootstrap")


class CheckError(Exception):
    """A check failed; the message is what the operator needs to read."""


def scout_binary(platform: str, component: str = "scout") -> str:
    return f"{component}-" + platform.replace("/", "-")


def chart_package(name: str, tag: str) -> str:
    return f"{name}-{tag}.tgz"


def artifact_names(platforms: list[str], tag: str) -> list[str]:
    """Every artifact of a release besides checksums.txt itself."""
    return sorted([scout_binary(p, scout) for scout in SCOUTS for p in platforms]
                  + [chart_package(c, tag) for c in CHARTS] + list(BUNDLES.values()) + [RECORD, THIRD_PARTY])


def content_markers(endpoints: dict, other_tiers: tuple = ()) -> tuple[dict, dict]:
    """(required, forbidden) markers per component for a build of the tier whose
    licensing endpoints are given: Standard / Pro carries its own tier's endpoint
    and no other tier's; CE carries no endpoint of any tier, and its Scout names
    its main package."""
    every_endpoint = tuple(markers[component] for markers in (endpoints, *other_tiers)
                           for component in ("scout", "frontend"))
    required = {"scout": (endpoints["scout"],), "frontend": (endpoints["frontend"],),
                "scout-ce": (CE_SCOUT_PATH,), "frontend-ce": ()}
    forbidden = {"scout": tuple(markers["scout"] for markers in other_tiers),
                 "frontend": tuple(markers["frontend"] for markers in other_tiers),
                 "scout-ce": every_endpoint, "frontend-ce": every_endpoint}
    return required, forbidden


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


def describe_marker(marker: str) -> str:
    if marker.startswith("path\t"):
        return "build info path " + marker.split("\t", 1)[1].strip()
    return f"endpoint {marker}"


def has_version(content: bytes, version: str) -> bool:
    """The release's own version string, not a dependency's: a Go binary with
    build info lists its modules as v<version> (in the module list and in file
    paths, @v<version>/), so an occurrence right after a "v" does not count."""
    return re.search(rb"(?<!v)" + re.escape(version.encode()), content) is not None


def content_failures(where: str, content: bytes, version: str, expected: tuple[str, ...],
                     forbidden: tuple[str, ...] = ()) -> list[str]:
    failures = []
    # One-directional: a build of another version does not contain this
    # version's string.
    if not has_version(content, version):
        failures.append(f"{where}: version {version} not found")
    for marker in expected:
        if marker.encode() not in content:
            failures.append(f"{where}: {describe_marker(marker)} not found")
    for marker in forbidden:
        if marker.encode() in content:
            failures.append(f"{where}: unexpected {describe_marker(marker)} compiled in")
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
                              required: dict, forbidden: dict) -> list[str]:
    """Version and markers inside every binary and bundle (content_markers)."""
    failures = []
    for scout in SCOUTS:
        for platform in platforms:
            name = scout_binary(platform, scout)
            failures += content_failures(name, (directory / name).read_bytes(), version,
                                         required[scout], forbidden[scout])
    for component, bundle in BUNDLES.items():
        chunks = bundle_chunks(directory / bundle)
        if not chunks:
            failures.append(f"{bundle}: no files match {BUNDLE_CHUNKS}")
        else:
            failures += content_failures(bundle, chunks, version, required[component], forbidden[component])
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
        failures.append(f"{tag} is not a release tag")
    elif record["channel"] != channel_of(tag):
        failures.append(f"recorded channel {record['channel']} does not match {tag}")
    return failures


def check_artifacts(directory: Path, tag: str, version: str) -> list[str]:
    record = load_record(directory)
    failures = tag_failures(record, tag)
    if record["version"] != version:
        failures.append(f"release.json says version {record['version']}, expected {version}")
    failures += checksum_failures(directory, artifact_names(record["platforms"], tag))
    if failures:
        return failures  # contents of a mismatched set prove nothing
    failures = artifact_content_failures(directory, record["platforms"], version,
                                         *content_markers(PRODUCTION_MARKERS))
    for chart in CHARTS:
        failures += check_chart(directory / chart_package(chart, tag), chart, tag)
    return failures


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
    required, forbidden = content_markers(PRODUCTION_MARKERS)
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
        failures += content_failures(where, b"\0".join(files.values()), version,
                                     required[component], forbidden[component])
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
    # Every image of the release, before the first push: a missing one would be
    # noticed only after the others and the version's tags were published.
    if sorted(record["images"]) != sorted(COMPONENTS):
        raise CheckError(f"{directory / RECORD} records images {sorted(record['images'])}, "
                         f"expected {sorted(COMPONENTS)}")
    rows = []
    for component, image in sorted(record["images"].items()):
        current = Layout(directory / image["layout"]).tag_descriptor(tag)["digest"]
        if current != image["digest"]:
            raise CheckError(f"{component}: layout is {current}, release.json recorded {image['digest']}")
        rows.append((component, image["name"], current))
    return rows


# ---- YAML scalars, edited in place --------------------------------------------------
# Chart files are documentation too (`helm show values` prints values.yaml), so
# they are edited line by line: comments and every other line stay as they are.
# Only scalars of block mappings are addressed; anything else is refused.

_KEY = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9_.-]+):(?P<rest>(?:\s.*)?)$")
_ITEM = re.compile(r"^(?P<indent> *)- ")


def _split_comment(rest: str) -> tuple[str, str]:
    """Value text and trailing comment of what follows "key:"."""
    quote = None
    for index, char in enumerate(rest):
        if quote:
            if char == quote and not (quote == '"' and rest[index - 1] == "\\"):
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or rest[index - 1] in " \t"):
            return rest[:index], rest[index:]
    return rest, ""


def _scalars(text: str):
    """(line number, path, value text, value column) of every block-mapping
    entry with a value on its line; value text is None for a block scalar.
    Keys inside sequence items get "[]" in their path, so no dotted path
    reaches into a list."""
    stack: list[tuple[int, str]] = []
    block_indent = None
    for number, line in enumerate(text.split("\n")):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue
            block_indent = None
        if not stripped or stripped.startswith("#") or stripped in ("---", "..."):
            continue
        item = _ITEM.match(line)
        if item:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, "[]"))
            # The item's first key sits two columns in; same length, same columns.
            line = " " * (indent + 2) + line[indent + 2:]
            indent += 2
        match = _KEY.match(line)
        if not match:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = match["key"]
        path = [entry for _, entry in stack] + [key]
        value, _ = _split_comment(match["rest"])
        if not value.strip():
            stack.append((indent, key))
            continue
        if value.strip()[0] in "|>":
            block_indent = indent
            yield number, path, None, match.start("rest")
            continue
        yield number, path, value, match.start("rest")


def _unquote(value: str) -> str:
    value = value.strip()
    if value.startswith('"'):
        return json.loads(value)
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value


def _find_scalar(text: str, path: str):
    target = path.split(".")
    hits = [hit for hit in _scalars(text) if hit[1] == target]
    if len(hits) != 1:
        raise CheckError(f"{path}: {'not found' if not hits else f'found {len(hits)} times'}")
    number, _, value, column = hits[0]
    if value is None or value.strip()[0] in "{[&*!":
        raise CheckError(f"{path} does not hold a plain scalar")
    return number, value, column


def get_scalar(text: str, path: str) -> str:
    return _unquote(_find_scalar(text, path)[1])


def set_scalar(text: str, path: str, value: str) -> str:
    """text with the scalar at the dotted path replaced by value (quoted)."""
    number, _, column = _find_scalar(text, path)
    lines = text.split("\n")
    _, comment = _split_comment(lines[number][column:])
    lines[number] = lines[number][:column] + " " + json.dumps(value) + (f"  {comment}" if comment else "")
    return "\n".join(lines)


def parse_sets(sets: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for item in sets:
        path, separator, value = item.partition("=")
        if not separator or not path:
            raise CheckError(f"--set {item!r}: expected path=value")
        pairs.append((path, value))
    return pairs


# ---- chart packages ---------------------------------------------------------------

def read_chart(package: Path) -> tuple[str, dict[str, bytes]]:
    """Chart name (the single top directory) and file contents of a package.
    Regular files only, under one root, no absolute or parent paths."""
    files: dict[str, bytes] = {}
    roots = set()
    with tarfile.open(package, mode="r:gz") as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if not parts or member.name.startswith("/") or ".." in parts:
                raise CheckError(f"{package.name}: unsafe path {member.name!r}")
            if member.isdir():
                continue
            if not member.isfile():
                raise CheckError(f"{package.name}: {member.name} is not a regular file")
            roots.add(parts[0])
            extracted = archive.extractfile(member)
            files[member.name] = extracted.read() if extracted else b""
    if len(roots) != 1:
        raise CheckError(f"{package.name}: expected one chart directory, found {sorted(roots)}")
    return roots.pop(), files


def check_chart(package: Path, name: str, tag: str) -> list[str]:
    """Name, version and appVersion of the chart and of every bundled subchart."""
    if not package.is_file():
        return [f"{package.name} missing"]
    try:
        root, files = read_chart(package)
    except CheckError as error:
        return [str(error)]
    if root != name:
        return [f"{package.name}: chart {root}, expected {name}"]
    failures = []
    for path, content in sorted(files.items()):
        parts = PurePosixPath(path).parts
        if parts[1:2] == ("charts",) and path.endswith(".tgz"):
            failures.append(f"{package.name}: {path} — subcharts are bundled unpacked")
        # <root>/Chart.yaml, <root>/charts/<sub>/Chart.yaml, and so on down.
        is_chart = (parts[-1] == "Chart.yaml" and len(parts) % 2 == 0
                    and all(parts[i] == "charts" for i in range(1, len(parts) - 1, 2)))
        if not is_chart:
            continue
        text = content.decode()
        expected = {"version": tag, "appVersion": tag}
        if len(parts) == 2:
            expected["name"] = name
        for key, value in expected.items():
            try:
                actual = get_scalar(text, key)
            except CheckError:
                actual = None
            if actual != value:
                failures.append(f"{package.name}: {path} {key}={actual!r}, expected {value!r}")
    if f"{name}/Chart.yaml" not in files:
        failures.append(f"{package.name}: no Chart.yaml")
    return failures


_IMAGE = re.compile(r"""^\s*(?:-\s+)?image:\s*["']?([^"'\s]+)["']?\s*$""", re.M)


def image_repository(reference: str) -> str:
    """Repository of an image reference: without @digest and without :tag."""
    base = reference.split("@", 1)[0]
    if ":" in base.rsplit("/", 1)[-1]:
        base = base[:base.rfind(":")]
    return base


def rendered_image_failures(manifest: str, tag: str, repositories: list[str],
                            absent: tuple[str, ...] = ()) -> list[str]:
    """Each of the release's own repositories present in a rendered chart and
    every use of it exactly <repository>:<tag> — the chart runs the images of
    its own version, by tag. The absent repositories must not appear at all:
    Server CE runs none of the Standard / Pro images, and the other way round."""
    images = sorted(set(_IMAGE.findall(manifest)))
    failures = []
    for repository in sorted(repositories):
        own = [image for image in images if image_repository(image) == repository]
        if not own:
            failures.append(f"{repository}: not in the rendered chart")
        failures += [f"{image}: expected {repository}:{tag}" for image in own if image != f"{repository}:{tag}"]
    for repository in sorted(absent):
        failures += [f"{image}: {repository} must not be rendered here" for image in images
                     if image_repository(image) == repository]
    return failures


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
    check.add_argument("--component", required=True, choices=COMPONENTS)
    for option in ("--layout", "--tag", "--version", "--platforms"):
        check.add_argument(option, required=True)

    images = sub.add_parser("record-images")
    images.add_argument("--dir", required=True)
    images.add_argument("--tag", required=True)
    images.add_argument("--image", action="append", required=True, help="component=name=layout-dir, repeated")

    publishable = sub.add_parser("check-publishable")
    publishable.add_argument("--dir", required=True)
    publishable.add_argument("--tag", required=True)

    chart = sub.add_parser("check-chart")
    for option in ("--chart", "--name", "--tag"):
        chart.add_argument(option, required=True)

    edit = sub.add_parser("yaml-set")
    edit.add_argument("--file", required=True)
    edit.add_argument("--set", action="append", required=True, help="path=value, repeated")

    rendered = sub.add_parser("check-rendered")
    rendered.add_argument("--manifest", required=True)
    rendered.add_argument("--tag", required=True)
    rendered.add_argument("--image", action="append", default=[], help="repository of this release, repeated")
    rendered.add_argument("--absent", action="append", default=[], help="repository that must not appear, repeated")

    file_digest = sub.add_parser("file-digest")
    file_digest.add_argument("--file", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "check-artifacts":
            failures = check_artifacts(Path(args.dir), args.tag, args.version)
            return report(failures, f"artifacts {args.tag} — checksums, version {args.version}, markers, charts")
        if args.command == "check-chart":
            return report(check_chart(Path(args.chart), args.name, args.tag), f"{args.name} {args.tag}")
        if args.command == "yaml-set":
            path = Path(args.file)
            text = path.read_text()
            for key, value in parse_sets(args.set):
                text = set_scalar(text, key, value)
            path.write_text(text)
        elif args.command == "check-rendered":
            failures = rendered_image_failures(Path(args.manifest).read_text(), args.tag, args.image,
                                               tuple(args.absent))
            return report(failures, f"{Path(args.manifest).name}: images of {args.tag}")
        elif args.command == "file-digest":
            print("sha256:" + sha256_file(Path(args.file)))
        if args.command == "digest":
            print(Layout(Path(args.layout)).tag_descriptor(args.tag)["digest"])
        elif args.command == "inspect":
            failures = inspect(args.component, Layout(Path(args.layout)), args.tag, args.version,
                               args.platforms.split(","))
            return report(failures, f"{args.component} — {args.platforms}, version {args.version}, "
                                    "markers, SBOM")
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
