# Security

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/lorcan10/ehls-protocol/security/advisories/new) for suspected vulnerabilities. Include the affected version, impact, and a minimal reproduction using synthetic data. Do not put real tokens, private files or sensitive device details in public issues, pull requests or logs.

## Supported scope

The hardening described below is included in version **0.2.1**. Earlier clones should update to the latest code before running the service.

This repository is a reference protocol library and local simulator. It is not an independently audited production DRM system, a hardware-attestation system, or a guarantee of whole-process secure erasure. No printer-control adapter is included.

The simulator binds to loopback by default, requires a bearer token for session operations, and keeps keys and instruction bytes out of API snapshots. Session authentication is checked before reading JSON, with a 4 KiB session-body limit and a 10-second body-read deadline. There is one shared service token and no tenant isolation; keep the service on a trusted local machine or behind your own authenticated backend and appropriate network protections.

Generated CLI tokens are printed to the local terminal for the demo. Treat terminal output as sensitive. Configure `EHLS_API_TOKEN` explicitly for unattended deployment; existing environment tokens are not printed. Never commit a working token or embed it in a public frontend bundle. Tokens in automated tests and the CI Docker job are synthetic and authorize only those temporary test processes.

Identity-derived session keys are not secret if their derivation inputs are known. Use authenticated transport and an authenticated ephemeral key exchange when implementing separate endpoints. Low-level serialization is not a substitute for signature verification, expected-index checks or input validation.

Page locking and wiping apply to managed buffers. Python objects and supporting libraries may contain other copies. The pool must be explicitly cleaned up, and deployed systems must account for swap, dumps, logs and device queues. Code review and automated checks do not establish universal non-persistence.

## Publication review — 3 November 2026

The publication review covered the tracked files and all four public commits existing at the start of the review (57 unique historical file blobs). Local secret detection, explicit credential/private-key pattern searches, and inspection of addresses and identifying data found no exposed operational credentials or private printer/network addresses. The secret detector flagged source-provenance checksums and an intentionally invalid test URL; these were reviewed as non-secrets. Public author identification and the origin story are intentional. No STL/drone geometry files or customer records were included. GitHub reported no secret-scanning alerts, no repository Actions secrets, no release assets and no Actions artifacts at the time of review.

The resolved 17-distribution runtime/API dependency set had no known vulnerabilities reported by `pip-audit` at review time. This result is specific to the installed versions, not every older version permitted by the dependency ranges.

The wider development environment contained outdated `pip` and `setuptools` installations with reported advisories. These tools were updated, the minimum build backend version was raised, and the security workflow upgrades the tooling before auditing it.

The review identified and corrected missing early request authentication/body limits, unsafe buffer ranges, incomplete pool shutdown cleanup, and redirect handling in the smoke-test client. Regression tests cover the corrections. The static Python scan is clean after these changes.

GitHub secret scanning and push protection are enabled, along with dependency alerts and automatic security fixes. CI checks tracked files for secret candidates, scans Python code and checks installed dependencies. These measures help detect issues; they do not prove that no vulnerability or misuse is possible. Publishing source does not itself open a connection to the author's computer or printer.
