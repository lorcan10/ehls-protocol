# Source provenance

This publication extracts the EHLS protocol core into an independent repository with a fresh Git history. `source-manifest.json` records the source commit, original file paths, and SHA-256 digests of the original selected files. Those digests describe the extraction inputs; they are not assertions that every published file remains byte-identical.

The extraction retains the original `shared` package and copies only `secure_zero.py` and `memory_lock_backends.py` from the gateway. This satisfies the lazy imports in `SecureBuffer` without publishing the gateway application.

Publication changes:

- Removed application vault encryption/decryption helpers from `shared/crypto.py`, and their corresponding tests.
- Corrected an overbroad security statement in the protocol module documentation and an outdated key-derivation description in the constants module. Cryptographic algorithms and wire constants are unchanged.
- Added standalone packaging, a synthetic test fixture, MIT license, documentation, a local simulation, and receiver-boundary tests.
- Retained historical claim references in source comments for traceability. These references do not assert a patent's legal status, demonstrate security guarantees, or indicate that private patent documents are part of this release.

No private Git history, patent drafts, deployment certificates, credentials, models, customer records, application UI, server services, or printer-control agent are included.
