"""Package the signed APK for ByteVirt's V1 beta update feed."""

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def compact(data):
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def utc(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def bundle(apk, version, build, key, output):
    published = datetime.fromisoformat(os.environ["RELEASE_DATE"].replace("Z", "+00:00"))
    notes = os.environ["RELEASE_NOTES"]
    if len(notes.encode("utf-8")) > 8192:
        raise ValueError("Release notes exceed the ByteVirt limit")
    size = apk.stat().st_size
    if not 0 < size <= 256 * 1024 * 1024:
        raise ValueError("APK size is outside the ByteVirt limit")
    with apk.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    manifest = {
        "schema": 1,
        "app": "dictionary",
        "channel": "beta",
        "platform": "android",
        "sequence": build,
        "status": "release",
        "published_at": utc(published),
        "expires_at": utc(published + timedelta(days=90)),
        "notes": notes,
        "version": version,
        "build": build,
        "min_client_build": 0,
        "asset": {
            "arch": "universal",
            "format": "apk",
            "identity": "com.toastfish.mobile",
            "signer_sha256": "228ac57f44fac1cce4f4f5e49ab98574435b599de9be7c43783878ca834af66f",
            "size": size,
            "sha256": digest,
            "url": f"/dictionary/beta/android/releases/{build}/package.apk",
        },
    }
    header = encode(compact({"alg": "RS256", "kid": "recite-beta-android-1"}))
    payload = encode(compact(manifest))
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key)],
        input=header + b"." + payload,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if len(signature) != 384:
        raise ValueError("Unexpected manifest key size")
    jws = compact({
        "protected": header.decode("ascii"),
        "payload": payload.decode("ascii"),
        "signature": encode(signature).decode("ascii"),
    })
    with output.open("xb") as destination, apk.open("rb") as source:
        destination.write(b"BVU1" + struct.pack(">I", len(jws)) + jws)
        shutil.copyfileobj(source, destination)


def check(bundle_file, live_manifest):
    with bundle_file.open("rb") as source:
        header = source.read(8)
        if header[:4] != b"BVU1":
            raise ValueError("Invalid update bundle")
        expected = json.loads(source.read(int.from_bytes(header[4:], "big")))
    if json.loads(live_manifest.read_bytes()) != expected:
        raise ValueError("The live update feed differs from the signed release")


if __name__ == "__main__":
    if sys.argv[1] == "check":
        check(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        apk, version, build, key, output = sys.argv[1:]
        bundle(Path(apk), version, int(build), Path(key), Path(output))
