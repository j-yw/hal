#!/usr/bin/env python3
"""Offline helpers executed only inside the independently pinned source build.

No package scripts, subprocesses, resolution, network calls or receipt issuance.
"""
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile

LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
GUEST = re.compile(r"[A-Za-z0-9._@+/-]+\Z")
PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z")
MAX_CONTENT = 512 << 20
PROFILE = pathlib.Path(__file__).resolve().parent

# Read-only header audit of the exact L8 cache pins. This is not a caller
# supplied extraction policy. Changing an archive pin requires a fresh audit.
NODETAR_KEYS = frozenset((
    "NODETAR.blksize", "NODETAR.blocks", "NODETAR.depth", "NODETAR.follow",
    "NODETAR.ignoreFiles.0", "NODETAR.ignoreFiles.1", "NODETAR.ignoreFiles.2",
    "NODETAR.package.author", "NODETAR.package.description",
    "NODETAR.package.devDependencies.mocha", "NODETAR.package.keywords.0",
    "NODETAR.package.keywords.1", "NODETAR.package.keywords.2", "NODETAR.package.keywords.3",
    "NODETAR.package.license", "NODETAR.package.main", "NODETAR.package.name",
    "NODETAR.package.repository", "NODETAR.package.scripts.test", "NODETAR.package.version",
    "NODETAR.type", "SCHILY.dev", "SCHILY.ino", "SCHILY.nlink", "gid", "path", "size", "uid",
))
ARCHIVE_FORMATS = {
    "types-retry-0.12.0.tgz": ("7c97db75aba1e8cb911b9ff349ddeae6153fd3b11fa3f3b772c1dd474ea9f8c8", "retry", False, frozenset()),
    "types-node-22.19.19.tgz": ("c32937b40ab720ef6242de0bf4c8b8e48f1e4a29fbb4cb9d9f596471ee58d5c4", "node v22.19", False, frozenset()),
    "http-proxy-agent-7.0.2.tgz": ("785f73faa92bfba8d61da20bf59325ab2b3dca1bbc0bbac523406f404d8a6f02", "package", True, frozenset()),
    "agent-base-7.1.4.tgz": ("7dd4a61668a9a4e8d4e903f1a254f94d53dafd3f316f2b9b597c5ad8c79cb57e", "package", True, frozenset()),
    "https-proxy-agent-7.0.6.tgz": ("960f89e8e5240882f64249d04a538421dd39d62ffacc138544647cc3251bc0e0", "package", True, frozenset()),
    "buffer-equal-constant-time-1.0.1.tgz": ("8f455159e342103e7854ed6a4cc73edbab144d857917c88edefea862f09fe75a", "package", False, NODETAR_KEYS),
    "mistralai-mistralai-2.2.6.tgz": ("972976d054d30dfcdc6bc537b1712e28860cef38ab9e3da09b5846e5a59ef43c", "package", False, frozenset(("mtime", "path", "size"))),
}
INDEX_DUPLICATES = {
    "http-proxy-agent-7.0.2.tgz": (6088, "fd33b43da34da60d4914780e13fae5d52a7faaa996d687eea5335128de148627"),
    "agent-base-7.1.4.tgz": (7324, "c6503bd5e007db8b73fedf07b6eaaf4a94d5541953f0d06c8a17d1644c29a0c5"),
    "https-proxy-agent-7.0.6.tgz": (7451, "30165586fac3becbc9dbf2b7b5bdaa802a77ac34af9926208f6e94a3bd87ef31"),
}


def archive_format(filename, verified_digest):
    expected = ARCHIVE_FORMATS.get(filename)
    if expected is None:
        return ("package", False, frozenset(), None)
    if expected[0] != verified_digest:
        reject()
    return expected[1:] + (INDEX_DUPLICATES.get(filename),)


def reject():
    raise ValueError("native stage: locked source or staged output rejected")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject()
        result[key] = value
    return result


def read_json(path):
    with open(path, "rb") as source:
        data = source.read((4 << 20) + 1)
    if len(data) > 4 << 20:
        reject()
    return json.loads(data, object_pairs_hook=unique_pairs)


def locks():
    result = {}
    for lane, count in (("l5", 52), ("l8", 142)):
        lines = (PROFILE.parent / lane / "cache.manifest").read_text().splitlines()
        if len(lines) != count or lines != sorted(lines):
            reject()
        for line in lines:
            digest, size, name = line.split("\t")
            if not LEAF.fullmatch(name) or name in result or not re.fullmatch(r"[a-f0-9]{64}", digest) or not size.isdecimal() or not 0 < int(size) <= MAX_CONTENT:
                reject()
            result[name] = (int(size), digest)
    native = read_json(PROFILE / "native-sources.lock.json")
    if len(native["records"]) != 11:
        reject()
    for record in native["records"]:
        name = record["name"]
        if name in result or not LEAF.fullmatch(name):
            reject()
        result[name] = (record["size"], record["sha256"])
    return result


def pinned(cache, name, pins):
    if name not in pins or not LEAF.fullmatch(name):
        reject()
    fd = os.open(cache / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(fd, "rb")
    before = os.fstat(fd)
    size, digest = pins[name]
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size != size:
        source.close()
        reject()
    measured = hashlib.file_digest(source, "sha256").hexdigest()
    after = os.fstat(fd)
    if measured != digest or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        source.close()
        reject()
    source.seek(0)
    return source


def seed(cache, destination, info_path, layout_path):
    pins = locks()
    if set(os.listdir(cache)) != set(pins):
        reject()
    info, expected = read_json(info_path), read_json(layout_path)
    if len(info) > 4096 or len(expected) != 55:
        reject()
    observed = set()
    for package in info.values():
        for download in package.get("downloads", []):
            directory, filename = package["dl_dir"], download["source"]
            if not LEAF.fullmatch(directory) or not LEAF.fullmatch(filename) or filename not in pins:
                reject()
            observed.add((directory, filename))
    wanted = [(record["directory"], record["filename"]) for record in expected]
    if wanted != sorted(observed):
        reject()
    for directory, filename in wanted:
        target = destination / directory
        target.mkdir(mode=0o700, exist_ok=True)
        if not stat.S_ISDIR(target.lstat().st_mode):
            reject()
        with pinned(cache, filename, pins) as source:
            fd = os.open(target / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                while block := source.read(1 << 20):
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())


def directory(root, relative):
    current = root
    for component in pathlib.PurePosixPath(relative).parts:
        if component in ("", ".", ".."):
            reject()
        current = current / component
        current.mkdir(mode=0o755, exist_ok=True)
        if not stat.S_ISDIR(current.lstat().st_mode):
            reject()
    return current


def unpack(source, destination, budget, policy=("package", False, frozenset(), None)):
    prefix, dot_index, pax_keys, duplicate_pin = policy
    duplicate_count = 0
    seen = set()
    with gzip.GzipFile(fileobj=source) as compressed:
        # At most one 64MiB expanded package is retained; reaching EOF also
        # verifies gzip CRC/truncation. Keeping the bounded bytes allows exact
        # trailing-zero checks that a buffered streaming tar reader can hide.
        expanded = compressed.read((64 << 20) + 1)
        if len(expanded) > 64 << 20:
            reject()
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                name = member.name.rstrip("/")
                if name == prefix and member.isdir() and name not in seen and not member.pax_headers:
                    seen.add(name)
                    continue
                if not name.startswith(prefix + "/") or set(member.pax_headers) - pax_keys or member.mode & 0o6000:
                    reject()
                for key, value in member.pax_headers.items():
                    if len(value) > 4096 or key == "path" and value != member.name or key == "size" and value != str(member.size):
                        reject()
                relative = name[len(prefix) + 1:]
                if dot_index and relative == "./dist/index.js":
                    relative = "dist/index.js"
                if duplicate_pin is not None and relative == "dist/index.js":
                    # Three measured, digest-bound archives repeat this exact
                    # regular member. Collapse only the expected ordered pair,
                    # after both independently match the measured content pin.
                    expected_names = ("package/./dist/index.js", "package/dist/index.js")
                    if duplicate_count >= 2 or name != expected_names[duplicate_count] or member.type != tarfile.REGTYPE or member.mode != 0o644 or member.uid != 0 or member.gid != 0 or member.mtime != 499162500 or member.pax_headers or member.size != duplicate_pin[0]:
                        reject()
                    with archive.extractfile(member) as body:
                        measured = hashlib.sha256(body.read(duplicate_pin[0] + 1)).hexdigest()
                    if measured != duplicate_pin[1]:
                        reject()
                    duplicate_count += 1
                    if duplicate_count == 2:
                        continue
                if not relative or not GUEST.fullmatch(relative) or str(pathlib.PurePosixPath(relative)) != relative or ".." in pathlib.PurePosixPath(relative).parts or relative in seen or len(seen) >= 65536 or relative.startswith("node_modules/"):
                    reject()
                seen.add(relative)
                parent = pathlib.PurePosixPath(relative).parent
                base = destination if str(parent) == "." else directory(destination, str(parent))
                target = base / pathlib.PurePosixPath(relative).name
                if member.isdir():
                    directory(destination, relative)
                elif member.isfile():
                    if member.size < 0 or member.size > budget[0]:
                        reject()
                    budget[0] -= member.size
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if member.mode & 0o111 else 0o644)
                    with os.fdopen(fd, "wb") as output, archive.extractfile(member) as body:
                        remaining = member.size
                        while remaining:
                            block = body.read(min(1 << 20, remaining))
                            if not block:
                                reject()
                            output.write(block)
                            remaining -= len(block)
                else:
                    reject()  # no archive links, devices, sparse entries or FIFO
            if any(expanded[archive.offset:]):
                reject()
    if duplicate_pin is not None and duplicate_count != 2:
        reject()


def install_pi(cache, target):
    pins = locks()
    with pinned(cache, "pi-shrinkwrap-0.82.1.json", pins) as source:
        wrap = json.load(source, object_pairs_hook=unique_pairs)
    packages = wrap["packages"]
    if wrap["lockfileVersion"] != 3 or len(packages) != 140 or packages[""]["name"] != "@earendil-works/pi-coding-agent" or packages[""]["version"] != "0.82.1":
        reject()
    root = directory(target, "usr/lib/pi")
    budget = [MAX_CONTENT]
    with pinned(cache, "pi-coding-agent-0.82.1.tgz", pins) as source:
        unpack(source, root, budget, archive_format("pi-coding-agent-0.82.1.tgz", pins["pi-coding-agent-0.82.1.tgz"][1]))
    if read_json(root / "package.json")["version"] != "0.82.1":
        reject()
    selected = []
    for installed, package in sorted(packages.items()):
        if not installed:
            continue
        if not installed.startswith("node_modules/") or str(pathlib.PurePosixPath(installed)) != installed or ".." in pathlib.PurePosixPath(installed).parts or package.get("link"):
            reject()
        segments = installed.split("node_modules/")[1:]
        if not all(PACKAGE.fullmatch(segment.rstrip("/")) for segment in segments):
            reject()
        name, version = segments[-1], package["version"]
        if not re.fullmatch(r"[0-9][A-Za-z0-9.+-]{0,127}", version):
            reject()
        filename = name.removeprefix("@").replace("/", "-") + "-" + version + ".tgz"
        if filename not in pins or package.get("resolved") != "https://registry.npmjs.org/" + name + "/-/" + name.split("/")[-1] + "-" + version + ".tgz":
            reject()
        compatible = ("os" not in package or "linux" in package["os"]) and ("cpu" not in package or "x64" in package["cpu"])
        # The pinned shrinkwrap omits libc metadata for these optional native
        # packages. The selected Buildroot ABI is musl, never GNU libc.
        if name == "@mariozechner/clipboard-linux-x64-gnu":
            compatible = False
        if not compatible:
            if package.get("optional") is not True:
                reject()
            continue
        destination = directory(root, installed)
        with pinned(cache, filename, pins) as source:
            unpack(source, destination, budget, archive_format(filename, pins[filename][1]))
        metadata = read_json(destination / "package.json")
        if metadata.get("name") != name or metadata.get("version") != version:
            reject()
        selected.append(installed)
    if "node_modules/@mariozechner/clipboard-linux-x64-musl" not in selected:
        reject()
    launcher = target / "usr/bin/pi"
    fd = os.open(launcher, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
    with os.fdopen(fd, "wb") as output:
        output.write(b'#!/bin/sh\nexec /usr/bin/node /usr/lib/pi/dist/cli.js "$@"\n')
    # Distributed package JS is installed byte-for-byte. No npm bin generation,
    # lifecycle script, registry lookup or independent TypeScript rebuild occurs.


if __name__ == "__main__":
    try:
        if len(sys.argv) == 6 and sys.argv[1] == "seed":
            seed(*(pathlib.Path(value) for value in sys.argv[2:]))
        elif len(sys.argv) == 4 and sys.argv[1] == "pi":
            install_pi(*(pathlib.Path(value) for value in sys.argv[2:]))
        else:
            reject()
    except (ValueError, KeyError, TypeError, OSError, EOFError, tarfile.TarError):
        print("native stage: locked source or staged output rejected", file=sys.stderr)
        sys.exit(1)
