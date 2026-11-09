# XtractR UI audit and product rules

## Gaps found

- The only visible verifier lived inside an already-selected local case. A recipient had no entry point for a ZIP sent by another examiner.
- The standalone verifier expected an unpacked directory, so a recipient had to extract the archive before checking it.
- A bundled public key could be mistaken for proof of the sender's identity. The UI needed an explicit out-of-band fingerprint step and a distinct “internally consistent” result.
- The previous X mark was generic and did not distinguish XtractR in the sidebar, browser tab, or feature artwork.
- The case dashboard had a stronger visual system than the pipeline, tables, verification surfaces, and report page.
- Large verification jobs needed file-size limits, upload and hashing progress, detailed path-level findings, and cleanup of temporary data.

## Changes in this build

- Added an always-visible **Verify a bundle** tool. It accepts the sender's ZIP, displays upload and verification progress, and returns individual checks with locations, expected values, and observed values.
- Added a direct recipient-verifier URL (`?view=received-verification`) for clear sharing from help, onboarding, and the README.
- Added `verify-bundle` to the standalone verifier. It reads the ZIP directly and copies only the database, seal, public key, and ledger into a temporary directory; it does not unpack the archive into the case workspace.
- Added package checks for the signed manifest, file hashes, SQLite integrity, Merkle seal, custody ledger, evidence inventory, optional five-hash evidence payload, signer fingerprint, and timestamp-token status. Malformed payload-inclusion flags are rejected instead of being coerced to true or false.
- Made signer identity a separate result. A key included in a bundle establishes internal consistency only; the recipient must compare its SHA-256 fingerprint with one received through a separate trusted channel to authenticate the signer.
- Added a custom XtractR evidence-trace symbol as a shared SVG mark and favicon.
- Applied one typography, color, spacing, focus, card, form, table, and status system across the dashboard and the existing workspace screens. Motion honors `prefers-reduced-motion`.
- Corrected verification result rendering so informational checks read as **INFO**, and multi-hash expected/observed values display as readable formatted data.
- Added matching dashboard and recipient-verifier screenshots to the README so the entry flow and the actual verification workspace are both visible before launch.
- Set the default upload limit to 8 GiB, with `XTRACTR_MAX_VERIFY_UPLOAD_BYTES` as an override. Temporary verifier files are removed when the task completes.

## Product and brand rules

### Typography

- Use the system UI sans stack for interface text. The local forensic interface must render without a remote font request.
- Use a monospace stack for fingerprints, hashes, file paths, timestamps, and machine identifiers.
- Use sentence case for page titles, buttons, form labels, and instructions. Reserve uppercase tracking for small section labels and metadata.
- Keep page titles around 28–36 px, section titles around 16–22 px, and body copy around 12–14 px. Do not use color alone to communicate a check result.

### Brand and color

- The XtractR mark represents evidence traces converging inside a scan frame. Use the shared `gui/static/xtractr-mark.svg` rather than a plain letter X.
- Use deep navy surfaces for the local workspace, blue for actions and navigation, green for passed checks, amber for warnings, and red for failed checks.
- Keep decorative glows behind content and reserve the strongest contrast for the task, status, and finding.

### Interaction and data display

- Keep verification tools available without requiring a case selection.
- Every long operation shows progress and a clear disabled/busy state. Every result identifies its scope and exact affected file or record.
- Show signer authentication separately from package integrity. Never label a self-signed bundle as trusted without an external fingerprint match.
- Use keyboard-visible focus, accessible labels, responsive layouts, and reduced-motion support.
- Keep received files out of case folders until the examiner explicitly takes a preservation or case-management action.

## Deployment boundary

The GUI remains a local workstation application using Flask's development server by default. Before exposing it to a network, deploy behind an authenticated production WSGI server with TLS and appropriate access controls. Parser process isolation is not an operating-system sandbox. RFC 3161 responses are not fully validated, so token presence is not trusted-time proof. These are system deployment and threat-model limits, not visual UI defects.
