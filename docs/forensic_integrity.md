# XtractR Forensic Integrity Model

## 1. Evidence Acquisition Integrity

Every file that enters the XtractR pipeline is subject to a **three-phase integrity check**:

### Phase 1: Pre-Hash (Source)
Before any copy operation, XtractR computes a SHA-256 hash of the source file. This hash is immediately recorded in the chain of custody log.

### Phase 2: Secure Copy
The file is copied to a working directory using `shutil.copy2()`, which preserves metadata (timestamps, permissions). Each copy is given a unique filename that includes the first 8 characters of its hash to prevent collisions.

### Phase 3: Post-Hash (Verification)
After copying, XtractR re-computes the SHA-256 hash of the destination file and compares it against the pre-hash. If the hashes do not match, the copy is deleted and the event is logged as `ACQUISITION_FAIL`.

## 2. Immutability Enforcement

XtractR probes write access at three depth levels within the evidence directory:
- **Root** — The top-level evidence directory
- **Mid-level** — A directory at the midpoint of the directory tree
- **Deepest** — The deepest subdirectory

If any write succeeds (canary file creation), the pipeline is **aborted** and the violation is logged. This ensures evidence is only processed from read-only media or write-protected mounts.

Canary files are always cleaned up regardless of outcome.

## 3. Merkle Root Sealing

After all artifacts are extracted, XtractR computes a **Merkle root** from the sorted SHA-256 hashes of all output artifacts:

1. All artifact output hashes are collected
2. Hashes are sorted lexicographically (deterministic ordering)
3. Sorted hashes are concatenated into a single string
4. SHA-256 is applied to the concatenation
5. The result is stored as `integrity.merkle_root` in `manifest.json`

This seal ensures that **any modification** to any output artifact will invalidate the root hash.

## 4. Independent Verification

The `xtractr_verify.py` tool performs completely independent verification:

1. Re-reads the manifest
2. Re-hashes every extracted artifact file
3. Compares each hash against the manifest claim
4. Re-computes the Merkle root from scratch
5. Compares the independent root against the manifest root

This tool uses no shared code with the pipeline, eliminating single-point-of-failure risks.

## 5. Chain of Custody Log

Every significant event is appended to `case_custody_ledger.jsonl` in the case directory:

```
TIMESTAMP | EVENT_TYPE | DETAILS | SRC:hash | DST:hash
```

Events include:
- `CASE_INIT` — Pipeline startup
- `ACQUISITION_START` / `ACQUISITION_SUCCESS` / `ACQUISITION_FAIL` — File copy operations
- `GOVERNANCE_PASS` / `GOVERNANCE_DENIAL` — Immutability and policy checks
- `NEGATIVE_SEARCH_AUDIT` — Searches that found no matching files
- `SCOPE_LIMIT_ENFORCED` — Encrypted databases detected but not extracted
- `CASE_SEAL` — Final Merkle root computation

## 6. Negative Search Auditing

When XtractR searches for a specific artifact type (e.g., SMS databases at `**/mmssms.db`) and finds nothing, this is explicitly logged. This prevents a malicious operator from claiming they searched for evidence without actually doing so.

## 7. HMAC Token Signing

Governance execution tokens are HMAC-SHA256 signed with a secret key. The signed payload includes:
- The raw governance token
- The target evidence path
- The execution timestamp

This binds the token to a specific evidence source and time window, preventing replay attacks.

## 8. Schema Validation

SQLite databases are opened in **read-only mode** (`?mode=ro`) and validated against expected table schemas before any data extraction. This prevents:
- SQL injection via crafted database files
- Parser crashes from unexpected column types
- Data extraction from wrong database versions
