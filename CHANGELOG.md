# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] - 2026-08-09

### Added
- Authenticated container format (v2.1): protocol and version header fields are now bound into AES-GCM associated data, preventing undetected tampering with these fields. Fully backward-compatible — existing v2.0 encrypted files still decrypt normally.
- Constant-time keyfile fingerprint comparison using `hmac.compare_digest` to prevent timing attacks.
- Path traversal and symlink protection on all file writes via a new `safe_open_write()` helper function.
- Pinned dependency lockfile with independently-verified hashes for reproducible installs (`requirements.lock`).

### Changed
- Increased Argon2id memory cost to 256 MiB per current OWASP guidance for high-security applications.
- Password no longer accepted as a CLI argument — interactive prompt or `GUN101_PASSWORD` environment variable only (to avoid exposure via process listings or shell history).
- Updated dependency floors in `pyproject.toml` remain compatible; lockfile now pins to latest stable versions (argon2-cffi==25.1.0, cryptography==50.0.0).

### Security Improvements
- Error messages are now generic ("Decryption failed") to prevent oracle attacks that could distinguish between wrong password, wrong keyfile, or corrupted container.
- All cryptographic operations now properly authenticate associated data (header fields) in AES-GCM.