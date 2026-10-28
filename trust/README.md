Public trust files from the key ceremony of 2026-10-28 (never a private key):
- `root_keys.json`: the public root key (kid `root1`); every camera image carries it.
- `keylist.json` + `keylist.sig`: the key list (version 1) signed by the root key. `cam-2026a` may sign `presenceeye-camera` and `presenceeye-updater`; `maint-2026a` may sign `presenceeye-maintenance` only.
The verify job checks every release against these files. A newer root-signed list replaces them when a release key is added or revoked.
