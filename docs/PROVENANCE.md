# Source provenance

This publication extracts the EHLS protocol core into an independent repository with a fresh Git history. `source-manifest.json` records the source commit, original file paths, and SHA-256 digests of the original selected files. Those digests describe the extraction inputs; they are not assertions that every published file remains byte-identical.

The extraction retains the original `shared` package and copies only `secure_zero.py` and `memory_lock_backends.py` from the gateway. This satisfies the lazy imports in `SecureBuffer` without publishing the gateway application.

Publication changes:

- Removed application vault encryption/decryption helpers from `shared/crypto.py`, and their corresponding tests.
- Corrected an overbroad security statement in the protocol module documentation and an outdated key-derivation description in the constants module. Cryptographic algorithms and wire constants are unchanged.
- Added standalone packaging, a synthetic test fixture, MIT license, documentation, a local simulation, and receiver-boundary tests.
- Retained historical claim references in source comments for traceability. These references do not assert a patent's legal status, demonstrate security guarantees, or indicate that private patent documents are part of this release.

No private Git history, patent drafts, deployment certificates, credentials, models, customer records, private application UI, private server services, or printer-control agent are included.

## Integration kit (0.2.0)

Added a new optional local simulator API (`ehls/`), CLI, browser example, JavaScript client, Docker configuration and integration guide. These are new public integration components; they do not export the private product backend or printer agent. The original source manifest still records the 0.1.0 extraction inputs.

## Publication security review

Hardened the public simulator request boundary and the extracted memory helpers, added regression tests, prevented smoke-test credential forwarding on redirects, and documented the review in `SECURITY.md`. These changes are specific to this public repository; the private source checkout was not edited.
