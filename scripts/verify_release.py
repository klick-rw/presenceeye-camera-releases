#!/usr/bin/env python3
"""Verifies a release folder BEFORE it is published (used by the publish workflow and runnable by hand).

    python3 scripts/verify_release.py release/pi-v1.0.0 --trust trust/

A release folder holds exactly two files: `<tag>.peye` (the signed package) and `SHA256SUMS`. The checks mirror what a camera
does (updater/package.py) plus guards against publishing the wrong thing:
  * tag and file names agree (`pi-v<version>` / `updater-v<version>`), nothing else is in the folder;
  * SHA256SUMS matches the package;
  * the package is a tar of exactly manifest.json, manifest.sig and payload.tar, no unsafe names, under 1.9 GiB;
  * the manifest names the right product for the tag, the tag's version, a positive sequence, and the payload's real size and SHA-256;
  * no file in the payload has a credential or private-key name, and no file starts with a private-key marker;
  * the manifest signature verifies with a key that a ROOT-SIGNED key list (trust/) lists for that product and has not revoked;
  * the signing key id is not a TEST or REHEARSAL key (those can never be published).
It needs only the Python standard library plus `cryptography` (for the signature checks). Exit status 1 on any failure.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile

PRODUCTS = {"pi": "presenceeye-camera", "updater": "presenceeye-updater"}
MAX_PACKAGE = int(1.9 * 1024 ** 3)
FORBIDDEN_NAMES = (".env", ".device_credential", ".mqtt_key.cache", "credential", "camera_config.json", "authorized_keys", "setup_wifi.json",
                   "id_rsa", "id_ed25519", "known_hosts")
FORBIDDEN_PREFIX = ("ssh_host_",)
FORBIDDEN_SUFFIX = (".key", ".pem", ".p12", ".pfx")
MARKERS = (b"-----BEGIN PRIVATE KEY", b"-----BEGIN RSA PRIVATE KEY", b"-----BEGIN EC PRIVATE KEY", b"-----BEGIN OPENSSH PRIVATE KEY",
           b"-----BEGIN ENCRYPTED PRIVATE KEY", b"-----BEGIN PGP PRIVATE KEY")
BLOCKED_KID = re.compile(r"^(TEST|REHEARSAL)", re.IGNORECASE)
TAG_RE = re.compile(r"^(pi|updater)-v(\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)$")


class Refused(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_folder(folder):
    tag = os.path.basename(os.path.normpath(folder))
    m = TAG_RE.match(tag)
    if not m:
        raise Refused(f"the folder name {tag!r} is not a release tag (pi-v<version> or updater-v<version>)")
    package = f"{tag}.peye"
    names = sorted(os.listdir(folder))
    if names != sorted([package, "SHA256SUMS"]):
        raise Refused(f"the folder must hold exactly {package} and SHA256SUMS, found {names}")
    path = os.path.join(folder, package)
    if os.path.getsize(path) > MAX_PACKAGE:
        raise Refused("the package is larger than 1.9 GiB (GitHub's asset limit is 2 GiB)")
    lines = [l for l in open(os.path.join(folder, "SHA256SUMS"), encoding="utf-8").read().splitlines() if l.strip()]
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-f]{64}  \*?" + re.escape(package), lines[0]):
        raise Refused("SHA256SUMS must be one line: '<sha256>  " + package + "'")
    if lines[0].split()[0] != sha256_file(path):
        raise Refused("SHA256SUMS does not match the package")
    return tag, m.group(1), m.group(2), path


def read_package(path):
    members = {}
    with tarfile.open(path, "r:") as tar:
        infos = tar.getmembers()
        if sorted(i.name for i in infos) != ["manifest.json", "manifest.sig", "payload.tar"]:
            raise Refused("the package must contain exactly manifest.json, manifest.sig and payload.tar")
        for i in infos:
            if not i.isfile():
                raise Refused(f"{i.name} is not a regular file")
            if i.name == "payload.tar":
                members[i.name] = tar.extractfile(i).read()
            else:
                if i.size > 1 << 22:
                    raise Refused(f"{i.name} is unreasonably large")
                members[i.name] = tar.extractfile(i).read()
    return members["manifest.json"], members["manifest.sig"], members["payload.tar"]


def check_payload(manifest, payload):
    p = manifest.get("payload") or {}
    if p.get("size") != len(payload) or p.get("sha256") != hashlib.sha256(payload).hexdigest():
        raise Refused("the manifest does not describe the payload (size or SHA-256 differ)")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
        for info in tar.getmembers():
            name = info.name
            if name.startswith("/") or ".." in name.split("/"):
                raise Refused(f"unsafe path in the payload: {name}")
            base = os.path.basename(name)
            if info.isfile() and (base in FORBIDDEN_NAMES or base.startswith(FORBIDDEN_PREFIX) or base.endswith(FORBIDDEN_SUFFIX)):
                raise Refused(f"a credential or private-key file is in the payload: {name}")
            if info.isfile() and info.size and not name.endswith((".so", ".pt", ".onnx", ".ogg", ".wav", ".mp3")):
                head = tar.extractfile(info).read(4096)
                if any(mk in head for mk in MARKERS):
                    raise Refused(f"a private-key marker is in {name}")


def check_signature(manifest_bytes, sig_bytes, product, trust_dir, allow_test_keys=False):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = json.loads(sig_bytes.decode("utf-8"))
        kid, alg, raw = sig["kid"], sig["alg"], base64.b64decode(sig["sig"], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        raise Refused(f"manifest.sig is not a signature file ({exc})")
    if alg != "ed25519":
        raise Refused(f"unsupported signature algorithm {alg!r}")
    if BLOCKED_KID.match(str(kid)) and not allow_test_keys:
        raise Refused(f"signed with {kid}: a TEST or REHEARSAL key can never be published")
    roots_path = os.path.join(trust_dir, "root_keys.json")
    if not all(os.path.isfile(os.path.join(trust_dir, n)) for n in ("root_keys.json", "keylist.json", "keylist.sig")):
        raise Refused("no trust files (trust/root_keys.json, keylist.json, keylist.sig): they come from the key ceremony")
    roots = {e["kid"]: Ed25519PublicKey.from_public_bytes(base64.b64decode(e["pub"]))
             for e in json.load(open(roots_path, encoding="utf-8")).get("keys", [])}
    list_bytes = open(os.path.join(trust_dir, "keylist.json"), "rb").read()
    list_sig = json.loads(open(os.path.join(trust_dir, "keylist.sig"), "rb").read().decode("utf-8"))
    doc = json.loads(list_bytes.decode("utf-8"))
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    root = roots.get(list_sig.get("kid"))
    if root is None:
        raise Refused("the key list is signed by a key that is not a root key")
    try:
        root.verify(base64.b64decode(list_sig["sig"], validate=True), canonical)
    except (InvalidSignature, ValueError, KeyError):
        raise Refused("the key list signature does not verify against the root key")
    entry = next((k for k in doc.get("keys", []) if k.get("kid") == kid), None)
    if entry is None:
        raise Refused(f"the signing key {kid} is not in the signed key list")
    if entry.get("revoked"):
        raise Refused(f"the signing key {kid} is revoked")
    if product not in (entry.get("products") or []):
        raise Refused(f"the key {kid} is not allowed to sign {product}")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["pub"])).verify(raw, manifest_bytes)
    except InvalidSignature:
        raise Refused("the manifest signature does not verify")
    return kid


def verify(folder, trust_dir, allow_test_keys=False):
    tag, kind, version, path = check_folder(folder)
    manifest_bytes, sig_bytes, payload = read_package(path)
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except ValueError:
        raise Refused("manifest.json is not JSON")
    if manifest.get("format") != 1:
        raise Refused("unsupported package format")
    if manifest.get("product") != PRODUCTS[kind]:
        raise Refused(f"the tag says {PRODUCTS[kind]} but the package is {manifest.get('product')!r}")
    if manifest.get("version") != version:
        raise Refused(f"the tag says version {version} but the package is {manifest.get('version')!r}")
    seq = manifest.get("sequence")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise Refused("the sequence must be a positive integer")
    check_payload(manifest, payload)
    kid = check_signature(manifest_bytes, sig_bytes, manifest["product"], trust_dir, allow_test_keys)
    return {"tag": tag, "product": manifest["product"], "version": version, "sequence": seq, "kid": kid,
            "sha256": sha256_file(path), "bytes": os.path.getsize(path), "prerelease": "-" in version}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--trust", default="trust")
    ap.add_argument("--allow-test-keys", action="store_true", help="tests only: never used by the publish workflow")
    a = ap.parse_args(argv)
    try:
        r = verify(a.folder, a.trust, a.allow_test_keys)
    except (Refused, tarfile.TarError, OSError) as exc:
        print(f"REFUSED  {exc}", file=sys.stderr)
        return 1
    print(json.dumps(r, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
