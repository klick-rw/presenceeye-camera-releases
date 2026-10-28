# Publishing a release (procedure)

A release is published by **pushing a release tag** to this repository. **Never push a `pi-v*` or `updater-v*` tag without the owner's written
approval of the release freeze.** The package must already be signed OFFLINE with the production release key (the firmware repository's
`deploy/RELEASE.md` has the steps up to this point).

1. Put the two files in `release/<tag>/`, where `<tag>` is `pi-v<version>` (camera application) or `updater-v<version>` (the camera's updater):
   - `<tag>.peye`: the signed package;
   - `SHA256SUMS`: one line, `<sha256>  <tag>.peye`.
2. Commit on a branch and open a pull request (or push a `ci/*` branch). The **verify** job checks the package the way a camera would
   (names, checksum, structure, manifest, no credentials or private-key markers, signature chain up to the root-signed key list in `trust/`) and refuses
   anything signed with a TEST or REHEARSAL key.
3. Merge to `main`. Then create an annotated tag on that commit and push it: `git tag -a pi-v1.0.0 -m "Camera 1.0.0" && git push origin pi-v1.0.0`.
4. The **publish** job verifies again and creates the GitHub release with exactly the two files (a version with a `-` such as `1.0.0-rc.1` is marked
   pre-release). It refuses to touch a release that already exists, and a tag that is not on `main`.
5. Register the release with the backend with the fields printed by `release_package.py record` (`githubTag`, `githubAssetName`); the backend decides which
   cameras are offered it (allow list first). Confirm the direct URL downloads the same bytes:
   `curl -L -o /tmp/x https://github.com/klick-rw/presenceeye-camera-releases/releases/download/<tag>/<tag>.peye && sha256sum /tmp/x`.

## The trust files
`trust/` holds the PUBLIC files from the key ceremony: `root_keys.json`, `keylist.json`, `keylist.sig`. Until they exist the verifier refuses every release.
Only public files ever go in this repository.

## Recommended repository settings (owner, in the GitHub settings)
Protect `main` (pull request and passing checks required), protect tags `pi-v*` and `updater-v*` (only the owner may create them), and enable release immutability if available.
