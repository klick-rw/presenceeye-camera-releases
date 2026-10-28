# PresenceEye camera firmware releases

Signed update packages for PresenceEye cameras. **This repository holds only signed, non-secret release artifacts.** Cameras download and verify
these automatically; you do not need to install anything by hand.

## What is here
Each release is a GitHub release tagged `pi-v<version>` (for example `pi-v1.0.0`) with exactly two files:
- `pi-v<version>.peye`: the signed update package for the camera application;
- `SHA256SUMS`: the SHA-256 of that package.

Updater packages (the camera's own update program) are published the same way under tags `updater-v<version>`.

## How a camera trusts a package
Every package carries a manifest signed with an Ed25519 release key. The camera holds only the matching PUBLIC keys (a signed key list rooted
in an offline root key) and refuses any package whose signature, product, version sequence, runtime or file hashes do not verify. Downloading
from this repository gives no extra trust: a package is installed only after the camera verifies it. Which cameras are offered which version is decided
by the PresenceEye backend, not by this repository.

## Checking a download yourself
    sha256sum -c SHA256SUMS

The package is a tar archive; do not run anything from it by hand.

## Security contact
Report a problem with a release privately to the PresenceEye team rather than in a public issue.

All rights reserved. These files are provided for updating PresenceEye cameras.
