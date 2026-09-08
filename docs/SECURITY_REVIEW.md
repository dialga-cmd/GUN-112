# Security Review

- **Project:** GUN-101
- **Reviewed version:** 2.1.0 (`v2.1.0` tag)
- **Date of review:** 8 September 2026
- **Reviewer(s):** Aditya Raj (maintainer), with the threat model and assurance
  case independently reviewed by contributor 25f3002130
- **Methods used:** manual design & code review, static analysis (ruff, bandit),
  dependency vulnerability audit (pip-audit), and review of the automated test
  suite (90 passing tests covering 88% of statements)

## Purpose

This report documents a security review of GUN-101 performing the review required
by the OpenSSF Best Practices Badge criterion `security_review`: it considers the
project's **security requirements** and its **security boundary**.

## Security requirements

The security requirements are defined in
[`docs/SECURITY.md`](SECURITY.md) and `docs/THREAT_MODEL.md`. The core
requirements are:

1. **Confidentiality:** file data is encrypted with AES-256-GCM and never
   stored or transmitted in cleartext.
2. **Integrity & authenticity:** the AES-GCM authentication tag detects any
   modification of ciphertext or associated data.
3. **Key security:** a 256-bit key is derived from the password (or keyfile)
   with Argon2id using memory-hard parameters; keys and nonces come only from
   `os.urandom()`.
4. **Tamper evidence:** both password and keyfile are authenticated; the
   container format version is authenticated.
5. **No oracle leakage:** all decryption failures produce the identical generic
   message `"Decryption failed"`.
6. **Safe file handling:** output paths are protected against symlink
   following and directory traversal escapes.
7. **Availability of the threat model:** `docs/THREAT_MODEL.md` enumerates the
   assumed adversary and explicitly out-of-scope items.

## Security boundary

**In scope:** the Python package `src/gun101/` (CLI, container format, key
derivation, cipher operations, keyfile handling, safe file I/O), the dependency
set declared in `pyproject.toml`, and the release/installation channel.

**Out of scope (documented in `docs/THREAT_MODEL.md` and `docs/SECURITY.md`):**

- Hardware/physical compromise of a machine holding key material in memory
  (Python objects cannot be guaranteed to be wiped from memory).
- Malicious Python runtimes or tampered standard libraries.
- Side-channel attacks below the language/OS layer.
- End-user phishing of the password itself.
- The host OS and its privilege model.

## What was reviewed

### Design

- **KDF:** Argon2id parameters (`time_cost=4`, `memory_cost=262144` KiB = 256 MiB,
  `parallelism=4`, 32-byte salt/hash) verified against OWASP password-storage
  guidance and confirmed not to be below recommended minimums. See
  `pyproject.toml` and `src/gun101/config.py`.
- **Cipher:** AES-256-GCM via `cryptography`; 12-byte random nonce generated per
  operation with `os.urandom`; 16-byte tag; no re-use of nonce across keys.
- **Container format:** HMAC-SHA256 over the header, authenticated version
  string, and authenticated keyfile-derived key — providing tamper evidence for
  both password-only and keyfile authentication. See `docs/CLI.md`.
- **Constant-time comparisons:** all comparisons of secrets (keyfile
  fingerprints, key material) use `hmac.compare_digest`.
- **Failure behaviour:** every failure path in `handler.py` raises the generic
  `"Decryption failed"`; the CLI maps all errors to a single generic message.
- **Safe file I/O:** `safe_open_write()` rejects symlink targets and paths that
  escape the working directory; keyfile generation refuses existing files,
  symlinks, and escaping paths.

### Code

- `ruff` over `E`, `F`, `W`, `I`, and `B` rule sets: clean.
- `bandit -r src`: 0 findings.
- Manual review of `cipher.py`, `kdf.py`, `handler.py`, `keyfile.py`, `cli.py`,
  and `config.py`.

### Dependencies

- Runtime dependencies are limited to `argon2-cffi` and `cryptography`, both
  widely audited and actively maintained.
- `pip-audit -r requirements.txt` in CI: no known vulnerabilities at review time.

### Tests

- 90 automated tests, including tamper-detection tests, password-policy tests,
  keyfile round-trips, container-format integrity tests, and negative tests for
  every security-relevant validation branch. Statement coverage 88%, enforced
  at ≥80% by CI (`--cov-fail-under=80`).

## Findings and dispositions

| # | Finding | Severity | Disposition |
|---|---------|----------|-------------|
| 1 | Memory wiping of derived keys cannot be guaranteed in Python (documented in `docs/SECURITY.md`). | Low | Accepted — out of scope per threat model. |
| 2 | No fuzzing harness for the container parser. | Low | Tracked in `ROADMAP.md` as a good-first-issue. |
| 3 | CLI error output is minimized to avoid oracle leakage (existing behaviour). | Info | Confirmed as the intended design. |
| 4 | Dependencies must be updated as new releases land. | Info | Handled by `pip-audit` in CI and range-pinned version constraints. |

No medium or higher severity issues were identified; no exploitable
vulnerabilities were found.

## Conclusion and next review

The project meets its documented security requirements within its stated
security boundary. A re-review will be performed when any security-relevant
change lands or when a new major version is released, and at least every 12
months.