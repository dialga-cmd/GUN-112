# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes yet. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to
contribute.

## [2.1.0] - 2026-08-09

### Added

- Authenticated container format (v2.1): protocol and version header fields are
  now bound into AES-GCM associated data, preventing undetected tampering with
  these fields. Fully backward-compatible — existing v2.0 encrypted files still
  decrypt normally.
- Constant-time keyfile fingerprint comparison using `hmac.compare_digest` to
  prevent timing attacks.
- Path traversal and symlink protection on all file writes via a new
  `safe_open_write()` helper function.
- Pinned dependency lockfile with independently-verified hashes for
  reproducible installs (`requirements.lock`).

### Changed

- Increased Argon2id memory cost to 256 MiB per current OWASP guidance for
  high-security applications (`ARGON2_MEMORY_COST = 262144` KiB).
- Password no longer accepted as a CLI argument — interactive prompt or
  `GUN101_PASSWORD` environment variable only (to avoid exposure via process
  listings or shell history).
- Updated dependency floors in `pyproject.toml` remain compatible; lockfile now
  pins to latest stable versions (`argon2-cffi==25.1.0`,
  `cryptography==50.0.0`).

### Fixed

- v2.0 containers stored the protocol and version header fields as
  unauthenticated JSON fields that could be silently edited; v2.1 binds them
  into AES-GCM associated data so any such tampering is detected and rejected.
- Keyfile fingerprints were previously compared with plain equality, which is
  vulnerable to timing attacks; they are now compared with
  `hmac.compare_digest`.

### Security

- Error messages are now generic ("Decryption failed") so a failure cannot be
  attributed to a wrong password, a wrong keyfile, or a corrupted container —
  preventing oracle-based probing.
- All cryptographic operations now authenticate associated data (header
  fields) in AES-GCM.

This project follows Semantic Versioning (semver.org).