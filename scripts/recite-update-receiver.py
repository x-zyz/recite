#!/usr/bin/env python3
"""Prepare, inspect and receive a signed ByteVirt release."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path("/opt/apphub/apps/site/updates/recite-publisher")
KEYS = Path("/etc/apphub/recite-update/keys")
MAGIC = b"BVU1"
MANIFEST_LIMIT = 65536
BLOCK = 1024 * 1024
ASSET_LIMIT = 256 * BLOCK
DISK_RESERVE = 512 * BLOCK
APPS = ("dictionary",)
CHANNELS = ("beta",)
PLATFORMS = ("android",)
COMMON = {
    "schema", "app", "channel", "platform", "sequence", "status",
    "published_at", "expires_at", "notes",
}
RELEASE = {"version", "build", "min_client_build", "asset"}
ASSET_FIELDS = {"arch", "format", "identity", "signer_sha256", "size", "sha256", "url"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def object_from_pairs(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def decode_json(raw):
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=object_from_pairs)
    require(isinstance(result, dict), "expected a JSON object")
    return result


def encode_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encode_b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_b64(encoded):
    require(matches(r"[a-zA-Z0-9_-]+", encoded), "invalid base64url")
    result = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    require(encode_b64(result) == encoded, "noncanonical base64url")
    return result


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def lane(app, channel, platform):
    require(app in APPS and channel in CHANNELS and platform in PLATFORMS, "invalid release lane")
    return f"{app}/{channel}/{platform}"


def validate_kid(kid):
    require(matches(r"[a-zA-Z0-9_-]{1,64}", kid), "invalid key ID")


def parse_time(value):
    require(matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
            "expected UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_manifest(payload, now=None):
    require(type(payload.get("schema")) is int and payload["schema"] == 1, "unsupported schema")
    location = lane(payload.get("app"), payload.get("channel"), payload.get("platform"))
    sequence = payload.get("sequence")
    require(integer(sequence, 1, 2**53 - 1), "invalid sequence")
    status = payload.get("status")
    require(status in ("paused", "release"), "invalid release status")
    require(payload.keys() == (COMMON | RELEASE if status == "release" else COMMON),
            "unexpected or missing manifest field")
    notes = payload["notes"]
    require(isinstance(notes, str) and len(notes.encode("utf-8")) <= 8192, "invalid release notes")
    start = parse_time(payload["published_at"])
    end = parse_time(payload["expires_at"])
    require(start < end <= start + timedelta(days=90), "invalid validity window")
    if now is not None:
        require(start <= now + timedelta(minutes=5) and now < end, "manifest outside validity window")
    if status == "paused":
        return location

    version = payload["version"]
    require(matches(r"(0|[1-9][0-9]{0,3})(\.(0|[1-9][0-9]{0,3})){2}", version), "invalid version")
    build = payload["build"]
    require(integer(build, 1, 999999999999), "invalid build")
    require(integer(payload["min_client_build"], 0, build - 1), "invalid minimum client build")
    asset = payload["asset"]
    require(isinstance(asset, dict) and asset.keys() == ASSET_FIELDS, "invalid asset fields")
    if payload["platform"] == "windows":
        major, minor, patch = map(int, version.split("."))
        require(build == major * 100000000 + minor * 10000 + patch, "Windows build mismatch")
        require(asset["arch"] == "x64" and asset["format"] in ("exe", "msix"), "invalid Windows asset")
    else:
        require(build <= 2100000000, "invalid Android versionCode")
        require(asset["arch"] == "universal" and asset["format"] == "apk", "invalid Android asset")
    require(matches(r"[A-Za-z0-9._-]{1,200}", asset["identity"]), "invalid package identity")
    if payload["platform"] == "android":
        require(matches(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+", asset["identity"]),
                "invalid Android package name")
    for field in ("signer_sha256", "sha256"):
        require(matches(r"[0-9a-f]{64}", asset[field]), f"invalid {field}")
    require(asset["signer_sha256"] != "0" * 64, "replace the example signer fingerprint")
    require(integer(asset["size"], 1, ASSET_LIMIT), "asset outside size limits")
    require(asset["url"] == f"/{location}/releases/{sequence}/package.{asset['format']}",
            "asset URL does not match its release")
    return location


def openssl(arguments, data):
    result = subprocess.run(["openssl", *arguments], input=data, capture_output=True, timeout=30)
    require(result.returncode == 0, "OpenSSL signature operation failed")
    return result.stdout


def sign(payload, kid, private_key):
    validate_kid(kid)
    protected = encode_b64(encode_json({"alg": "RS256", "kid": kid}))
    body = encode_b64(encode_json(payload))
    message = f"{protected}.{body}".encode("ascii")
    arguments = ["dgst", "-sha256", "-sign", str(private_key)]
    if "BYTEVIRT_SIGNING_PASSPHRASE" in os.environ:
        arguments.extend(["-passin", "env:BYTEVIRT_SIGNING_PASSPHRASE"])
    signature = openssl(arguments, message)
    require(len(signature) == 384, "use an RSA 3072-bit signing key")
    return encode_json({"protected": protected, "payload": body, "signature": encode_b64(signature)})


def unpack(raw):
    require(0 < len(raw) <= MANIFEST_LIMIT, "manifest outside size limits")
    envelope = decode_json(raw)
    require(envelope.keys() == {"protected", "payload", "signature"}, "invalid JWS envelope")
    protected = decode_json(decode_b64(envelope["protected"]))
    require(protected.keys() == {"alg", "kid"} and protected["alg"] == "RS256", "invalid JWS header")
    validate_kid(protected["kid"])
    signature = decode_b64(envelope["signature"])
    require(len(signature) == 384, "invalid RSA signature size")
    body = decode_b64(envelope["payload"])
    message = f"{envelope['protected']}.{envelope['payload']}".encode("ascii")
    return protected["kid"], body, signature, message


def verify_manifest(raw, key_id, public_key, scratch):
    kid, body, signature, message = unpack(raw)
    require(kid == key_id, "unexpected manifest signing key")
    signature_file = scratch / "signature.tmp"
    signature_file.write_bytes(signature)
    openssl(["dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature_file)], message)
    payload = decode_json(body)
    validate_manifest(payload, datetime.now(timezone.utc))
    return payload


def inspect_asset(stream, size, destination=None):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = stream.read(min(remaining, BLOCK))
        require(block, "incomplete asset")
        digest.update(block)
        if destination is not None:
            destination.write(block)
        remaining -= len(block)
    require(not stream.read(1), "unexpected trailing data")
    return digest.hexdigest()


def read_bundle(stream, kid, key, scratch, expected_lane=None, stage=None):
    require(stream.read(4) == MAGIC, "invalid bundle header")
    length = stream.read(4)
    require(len(length) == 4, "incomplete manifest length")
    size = int.from_bytes(length, "big")
    require(0 < size <= MANIFEST_LIMIT, "manifest outside size limits")
    raw = stream.read(size)
    require(len(raw) == size, "incomplete manifest")
    payload = verify_manifest(raw, kid, key, scratch)
    location = lane(payload["app"], payload["channel"], payload["platform"])
    require(expected_lane is None or expected_lane == location, "deployment key is scoped to a different lane")
    asset = payload.get("asset")
    if asset is None:
        require(not stream.read(1), "paused release has unexpected data")
    elif stage is None:
        require(inspect_asset(stream, asset["size"]) == asset["sha256"], "asset hash mismatch")
    else:
        free = shutil.disk_usage(stage).free
        require(free >= asset["size"] + DISK_RESERVE, "insufficient disk space after reserve")
        package = stage / Path(asset["url"]).name
        with package.open("xb") as destination:
            require(inspect_asset(stream, asset["size"], destination) == asset["sha256"], "asset hash mismatch")
            destination.flush()
            os.fsync(destination.fileno())
        package.chmod(0o644)
    return raw, payload


def prepare(args):
    inputs = (args.spec, args.asset, args.private_key, args.public_key)
    require(args.output.suffix == ".bvu", "output must end in .bvu")
    require(args.output.resolve() not in {path.resolve() for path in inputs if path is not None},
            "output overlaps an input")
    payload = decode_json(args.spec.read_bytes())
    asset = payload.get("asset")
    if args.asset:
        require(isinstance(asset, dict), "release spec requires asset metadata")
        size = args.asset.stat().st_size
        require(0 < size <= ASSET_LIMIT, "asset outside size limits")
        location = lane(payload.get("app"), payload.get("channel"), payload.get("platform"))
        with args.asset.open("rb") as package:
            digest = inspect_asset(package, size)
        asset.update(size=size, sha256=digest,
                     url=f"/{location}/releases/{payload.get('sequence')}/package.{asset.get('format')}")
        require(args.asset.suffix == "." + asset["format"], "package extension mismatch")
    require((payload.get("status") == "release") == bool(args.asset), "asset required for release only")
    validate_manifest(payload, datetime.now(timezone.utc))
    raw = sign(payload, args.kid, args.private_key)
    require(len(raw) <= MANIFEST_LIMIT, "manifest outside size limits")
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temp:
        bundle = Path(temp) / "release.bvu"
        with bundle.open("wb") as target:
            target.write(MAGIC + len(raw).to_bytes(4, "big") + raw)
            if args.asset:
                with args.asset.open("rb") as source:
                    actual = inspect_asset(source, asset["size"], target)
                    require(actual == asset["sha256"], "asset changed while preparing bundle")
        with bundle.open("rb") as source:
            read_bundle(source, args.kid, args.public_key, Path(temp))
        os.replace(bundle, args.output)
    print(f"Prepared sequence {payload['sequence']}")


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_synced(path, contents):
    with path.open("xb") as handle:
        handle.write(contents)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o644)


def publish(site, stage, raw, payload):
    latest = site / "latest.json"
    if latest.exists():
        current = latest.read_bytes()
        sequence = decode_json(unpack(current)[1])["sequence"]
        require(payload["sequence"] > sequence or raw == current, "sequence is stale or already used")
    target = site / "releases" / str(payload["sequence"])
    if target.exists():
        require((target / ".manifest.jws").read_bytes() == raw, "sequence already has different bytes")
        asset = payload.get("asset")
        if asset:
            with (target / Path(asset["url"]).name).open("rb") as source:
                require(inspect_asset(source, asset["size"]) == asset["sha256"], "existing release is corrupt")
    else:
        write_synced(stage / ".manifest.jws", raw)
        stage.chmod(0o755)
        sync_dir(stage)
        os.rename(stage, target)
        sync_dir(stage.parent)
    sync_dir(target.parent)
    if latest.exists() and latest.read_bytes() == raw:
        sync_dir(site)
        return
    candidate = stage.parent / "candidate.json"
    write_synced(candidate, raw)
    os.replace(candidate, latest)
    sync_dir(site)
    sync_dir(candidate.parent)


def receive(app, channel, platform, kid):
    import fcntl

    os.environ["PATH"] = "/usr/bin:/bin"
    location = lane(app, channel, platform)
    validate_kid(kid)
    require(os.environ.get("SSH_ORIGINAL_COMMAND") == "publish-v1", "invalid SSH command")
    site = ROOT / location
    key = KEYS / location / f"{kid}.pem"
    inbox = ROOT / ".state" / "inbox"
    with (ROOT / ".state" / "locks" / "publish.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(inbox.stat().st_dev == (site / "releases").stat().st_dev == site.stat().st_dev,
                "staging, releases and latest must share a filesystem")
        with tempfile.TemporaryDirectory(dir=inbox, prefix="release-") as temp:
            scratch = Path(temp)
            stage = scratch / "release"
            stage.mkdir(mode=0o700)
            raw, payload = read_bundle(sys.stdin.buffer, kid, key, scratch, location, stage)
            publish(site, stage, raw, payload)
    print(f"Published {location} sequence {payload['sequence']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--spec", type=Path, required=True)
    prep.add_argument("--asset", type=Path)
    prep.add_argument("--private-key", type=Path, required=True)
    prep.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    for command in (prep, verify):
        command.add_argument("--kid", required=True)
        command.add_argument("--public-key", type=Path, required=True)
    remote = sub.add_parser("receive")
    for argument in ("app", "channel", "platform", "kid"):
        remote.add_argument(argument)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args)
        elif args.command == "verify":
            with tempfile.TemporaryDirectory() as temp, args.bundle.open("rb") as source:
                _, payload = read_bundle(source, args.kid, args.public_key, Path(temp))
            print(json.dumps(payload, ensure_ascii=True, indent=2))
        else:
            receive(args.app, args.channel, args.platform, args.kid)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Release rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
