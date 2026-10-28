"""scripts/verify_release.py, with throw-away keys generated at test time (nothing here is a real key)."""
import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import verify_release as vr  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def b64pub(key):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def tar_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Release(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root, self.rel = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.trust = os.path.join(self.tmp, "trust")
        os.makedirs(self.trust)
        self.write_trust()

    def write_trust(self, kid="PROD-REL-1", products=("presenceeye-camera",), revoked=False, root_kid="PROD-ROOT-1"):
        doc = {"format": 1, "listVersion": 1, "keys": [{"kid": kid, "pub": b64pub(self.rel), "products": list(products), "revoked": revoked}]}
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        json.dump({"keys": [{"kid": root_kid, "pub": b64pub(self.root)}]}, open(os.path.join(self.trust, "root_keys.json"), "w"))
        open(os.path.join(self.trust, "keylist.json"), "wb").write(canonical)
        sig = {"kid": root_kid, "alg": "ed25519", "sig": base64.b64encode(self.root.sign(canonical)).decode()}
        open(os.path.join(self.trust, "keylist.sig"), "wb").write(json.dumps(sig).encode())

    def make(self, tag="pi-v1.0.0", kid="PROD-REL-1", product="presenceeye-camera", version="1.0.0", payload_files=None, sums_ok=True,
             extra=None, mutate_payload=False, sign_key=None):
        folder = os.path.join(self.tmp, "release", tag)
        os.makedirs(folder, exist_ok=True)
        payload = tar_bytes(payload_files or {"main.py": b"print(1)\n", "VERSION": version.encode()})
        manifest = {"format": 1, "product": product, "version": version, "sequence": 7, "channel": "stable", "minUpdater": "1.0.0", "rollback": False,
                    "runtime": {"lockSha256": "0" * 64, "modelsSha256": "1" * 64}, "files": [],
                    "payload": {"name": "payload.tar", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}}
        mb = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        sig = json.dumps({"kid": kid, "alg": "ed25519", "sig": base64.b64encode((sign_key or self.rel).sign(mb)).decode()}).encode()
        if mutate_payload:
            payload = payload + b"x"
        pkg = tar_bytes({"manifest.json": mb, "manifest.sig": sig, "payload.tar": payload})
        open(os.path.join(folder, f"{tag}.peye"), "wb").write(pkg)
        digest = hashlib.sha256(pkg).hexdigest() if sums_ok else "f" * 64
        open(os.path.join(folder, "SHA256SUMS"), "w").write(f"{digest}  {tag}.peye\n")
        for name in (extra or []):
            open(os.path.join(folder, name), "w").write("x")
        return folder

    def verify(self, folder, **kw):
        return vr.verify(folder, self.trust, **kw)

    def refused(self, folder, fragment, **kw):
        with self.assertRaises(vr.Refused) as cm:
            self.verify(folder, **kw)
        self.assertIn(fragment, str(cm.exception))

    def test_a_correct_production_release_passes(self):
        r = self.verify(self.make())
        self.assertEqual((r["tag"], r["product"], r["version"], r["sequence"], r["kid"], r["prerelease"]), ("pi-v1.0.0", "presenceeye-camera", "1.0.0", 7, "PROD-REL-1", False))

    def test_a_release_candidate_is_marked_prerelease(self):
        self.assertTrue(self.verify(self.make(tag="pi-v1.0.0-rc.1", version="1.0.0-rc.1"))["prerelease"])

    def test_test_and_rehearsal_keys_can_never_be_published(self):
        for kid in ("TEST-release", "test-x", "REHEARSAL-1"):
            with self.subTest(kid=kid):
                self.write_trust(kid=kid)
                self.refused(self.make(kid=kid), "can never be published")
        self.write_trust(kid="TEST-release")
        self.assertEqual(self.verify(self.make(kid="TEST-release"), allow_test_keys=True)["kid"], "TEST-release")

    def test_wrong_folder_names_and_extra_files(self):
        self.refused(self.make(tag="v1.0.0"), "not a release tag")
        self.refused(self.make(tag="pi-v1.0.1", version="1.0.1", extra=["notes.txt"]), "exactly")

    def test_checksum_and_package_integrity(self):
        self.refused(self.make(sums_ok=False), "does not match the package")
        self.refused(self.make(tag="pi-v1.0.2", version="1.0.2", mutate_payload=True), "does not describe the payload")

    def test_tag_must_agree_with_the_package(self):
        self.refused(self.make(tag="updater-v1.0.0"), "presenceeye-updater")
        self.refused(self.make(tag="pi-v1.0.3", version="1.0.4"), "tag says version")

    def test_credentials_and_private_keys_in_the_payload_are_refused(self):
        for name in (".env", "etc/ssh_host_ed25519_key", "x/ca.key", "data/camera_config.json", "setup_wifi.json"):
            with self.subTest(name=name):
                self.refused(self.make(tag="pi-v1.1.0", version="1.1.0", payload_files={name: b"x"}), "credential or private-key file")
        marker = b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\nabc"
        self.refused(self.make(tag="pi-v1.1.1", version="1.1.1", payload_files={"notes.txt": marker}), "private-key marker")

    def test_signature_chain_is_enforced(self):
        self.refused(self.make(sign_key=Ed25519PrivateKey.generate()), "manifest signature does not verify")
        self.write_trust(revoked=True)
        self.refused(self.make(), "revoked")
        self.write_trust(products=("presenceeye-updater",))
        self.refused(self.make(), "not allowed to sign")
        self.write_trust()
        os.unlink(os.path.join(self.trust, "keylist.sig"))
        self.refused(self.make(), "no trust files")

    def test_a_tampered_key_list_is_refused(self):
        folder = self.make()
        path = os.path.join(self.trust, "keylist.json")
        original = open(path, "rb").read()
        open(path, "wb").write(original.replace(b"presenceeye-camera", b"presenceeye-updater"))
        self.refused(folder, "key list signature does not verify")

    def test_the_command_line_exits_nonzero_on_refusal(self):
        self.assertEqual(vr.main([self.make(kid="TEST-r"), "--trust", self.trust]), 1)


if __name__ == "__main__":
    unittest.main()
