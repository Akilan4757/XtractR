# XtractR Integrity and Export Behavior

This document describes controls implemented in the current code. It does not treat a warning, a local key, or process isolation as proof of an external trust boundary.

## Evidence baseline and export

- The current workflow records a path and computes a SHA-256 baseline during **Scan**. Hashing does not currently occur at ingest.
- Before export, XtractR enumerates the source again, checks for added and missing paths, and streams every file through SHA-256, SHA-512, SHA-384, SHA-1, and MD5. SHA-1 and MD5 are provided for compatibility and must not be used alone to establish integrity.
- Export aborts when the source cannot be checked or the files differ from the baseline.
- The ZIP includes `README_EVIDENCE.md` and `evidence_manifest.json`. By default, it also includes source file bytes under `evidence/`. The GUI export step lets the operator omit those bytes when storage or transfer size is a constraint.
- The manifest and its signature cover the README and machine-readable inventory. The independent verifier and GUI verification workspace re-hash bundled evidence against all five listed digests when the evidence payload is present.
- The evidence tree uses ordered, domain-separated Merkle hashing over records containing path, size, modification time, and SHA-256. New seals use `format_version: 2`; the verifier currently rejects legacy formats rather than interpreting them as v2.

## Verification and trust

- The CLI verifier requires an out-of-band `--expect-fingerprint` by default. `--allow-unpinned` reports internal consistency but does not authenticate the signer.
- The GUI lets the reviewer enter a trusted public-key fingerprint and reports database, seal, signature, custody-ledger, JSONL, manifest, source, and ZIP findings with their file or event locations.
- The GUI reports an RFC 3161 token as a warning. It does not parse the response status, nonce, imprint, TSA certificate chain, or revocation data, so token presence is not proof of a trusted time anchor.

## Current limits

- Plugin execution uses child processes and platform-dependent resource limits. It is not an OS sandbox; plugins can still access host resources, and Windows does not apply the Unix `rlimit` limits.
- Evidence-derived SQLite files are not yet handled through a shared read-only, defensive database helper.
- Evidence acquisition, write-blocker attestation, multiple source records per case, disk partition enumeration, and backward-compatible legacy verification are not implemented.
