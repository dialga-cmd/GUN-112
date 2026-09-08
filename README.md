# GUN-101

A simple, secure file encryption tool using **AES-256-GCM** and **Argon2id**.

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14526/badge)](https://www.bestpractices.dev/projects/14526)

## What problem does this solve?

If a laptop is lost, a cloud drive is breached, or a USB stick falls into the wrong hands, the files on it are exposed. GUN-101 protects files at rest: it encrypts them so that only someone with the correct password (and, optionally, a separate keyfile) can read them, and any tampering with an encrypted file is detected and rejected before it is opened.

## Overview

GUN-101 encrypts files with authenticated encryption, providing confidentiality and integrity. It supports two modes:

1. **Password-only**: Encryption key derived from password alone
2. **Password + keyfile**: Two-factor protection requiring both password and a separate keyfile

The design prioritizes correctness and transparency over complexity or marketing claims.

The tool uses a versioned container format (currently v2.1) to allow for future improvements while maintaining backward compatibility with v2.0 encrypted files.

## Cryptographic Primitives

- **Key Derivation**: Argon2id (memory-hard, winner of the Password Hashing Competition 2015)
- **Encryption**: AES-256-GCM (authenticated encryption with associated data, NIST SP 800-38D)
- **Salt**: 32 bytes random per encryption
- **Nonce**: 12 bytes random per encryption (GCM recommended size)
- **Key Length**: 32 bytes (256 bits)

## Security Properties

What GUN-101 **does** provide:
- Confidentiality: Passive attackers cannot decrypt without the password (and keyfile, if used)
- Integrity: Any tampering with the encrypted container is detected and rejected before returning plaintext
- Brute-force resistance: Argon2id maximizes the cost of guessing passwords (memory-hard, GPU-resistant)
- Two-factor protection: When a keyfile is used and stored separately, an attacker who knows the password still cannot decrypt without the physical keyfile

What GUN-101 **does NOT** provide:
- Protection against malware on the encryption/decryption machine
- Protection if both the encrypted file and keyfile are stolen (two-factor mode only)
- Protection against side-channel attacks, coercion, or future cryptographic breaks
- Secure deletion of plaintext or temporary files

## Usage

### Installation

```bash
pip install gun101
```

### Generate a keyfile (for two-factor mode)

```bash
gun101 generate-keyfile /path/to/keyfile
```
This creates a 32-byte random keyfile and prints its SHA-256 fingerprint. Store the keyfile on a separate device (e.g., USB drive) and record the fingerprint.

### Encrypt a file

```bash
gun101 encrypt secrets.pdf --keyfile /path/to/keyfile
```
Encrypts `secrets.pdf` to `secrets.pdf.gun101`. Omit `--keyfile` for password-only mode.

**Password requirements**: Must be at least 10 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.

**Password input**: Password can be entered via interactive prompt or provided through the `GUN101_PASSWORD` environment variable (see [Security Design](docs/SECURITY.md) for trade-offs).

### Decrypt a file

```bash
gun101 decrypt secrets.pdf.gun101 --keyfile /path/to/keyfile
```
Decrypts to `secrets.pdf` (removes `.gun101` extension). Omit `--keyfile` for password-only mode.

**Password requirements**: Must be at least 10 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.

**Password input**: Password can be entered via interactive prompt or provided through the `GUN101_PASSWORD` environment variable (see [Security Design](docs/SECURITY.md) for trade-offs).

### Verify a keyfile fingerprint

```bash
gun101 keyfile-fingerprint /path/to/keyfile
```
Prints the SHA-256 fingerprint to confirm you have the correct keyfile.

## Command Reference

The complete reference for the external interface — every command, input,
output, environment variable, exit code, and the container file format — is in
[docs/CLI.md](docs/CLI.md). A summary follows:

```
gun101 encrypt <file> [--keyfile <path>] [--output <path>]
  Encrypts <file>. If --output not given, writes to <file>.gun101

gun101 decrypt <file> [--keyfile <path>] [--output <path>]
  Decrypts <file>. If --output not given, strips .gun101 extension or appends .decrypted

gun101 generate-keyfile <path>
  Generates a keyfile at <path>. Prints fingerprint after generation.

gun101 keyfile-fingerprint <path>
  Prints the SHA-256 fingerprint of a keyfile.
```

## Design Decisions

### Why Argon2id?
- Resists GPU/ASIC cracking via high memory usage
- Resists side-channel attacks via data-independent memory access
- Recommended by OWASP and NIST SP 800-63B for password hashing

### Password Composition Rules
GUN-101 enforces a password policy requiring at least 10 characters with uppercase, lowercase, digit, and special character. While NIST 800-63B de-emphasizes composition rules for online authentication (where rate limiting applies), GUN-101 retains them for the following reasons:
1. **Offline attack scenario**: Encryption tools face offline brute-force attacks where rate limiting cannot be applied
2. **Entropy enhancement**: Composition rules increase password entropy, making brute-force attacks more expensive
3. **User familiarity**: Many users are accustomed to these rules and they provide a baseline strength guarantee
4. **Compatibility with Argon2id**: Combined with memory-hard Argon2id, this provides strong protection against guessing attacks

Users seeking maximum security should consider using longer passphrases (14+ characters) that meet these requirements, or randomly generated passwords of sufficient length.

### Why AES-256-GCM?
- Provides both confidentiality and integrity (authenticated encryption)
- Eliminates padding oracle vulnerabilities present in CBC mode
- Standardized and widely vetted

### Key Concatenation
The keyfile bytes are appended to the password UTF-8 bytes before Argon2id input. This ensures the derived key depends on both factors.

### Error Handling
All errors produce generic messages (e.g., "Decryption failed") to avoid leaking information about what went wrong.

## Limitations

- **No perfect memory wiping**: Python's garbage collection prevents guaranteed key erasure from memory
- **Password strength enforcement**: Passwords must be at least 10 characters long and contain uppercase, lowercase, digit, and special character
- **No forward secrecy**: Compromised key reveals all past messages encrypted with it
- **No deniability**: Encrypted files are identifiable by their structure

## Dependencies

- Python >= 3.9
- argon2-cffi >= 23.1.0
- cryptography >= 42.0.2

## Reproducible Builds

For security-critical applications, exact dependency versions should be pinned to prevent supply chain attacks and ensure reproducible builds. A `requirements.lock` file is provided with exact versions and cryptographic hashes:

```bash
pip install --require-hashes -r requirements.lock
```

This lockfile includes:
- argon2-cffi==25.1.0
- cryptography==50.0.0

## Testing

Run the test suite with:

```bash
pytest tests/ -v
```

Coverage of the `gun101` package is measured with `pytest-cov` and must stay at
80% or above (see `pyproject.toml`); recent runs report ~88%.

## Feedback and Contributing

Found a bug or have a feature request? Please [open a GitHub issue](https://github.com/dialga-cmd/gun101/issues/new/choose) — use the bug report or feature request template.

Want to contribute? Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding standards, and security-sensitive contribution rules, then open a pull request.

**Security vulnerabilities must not be reported as public issues.** Report them privately by emailing `adityaraj1234@duck.com` (see [Reporting a Security Vulnerability](#reporting-a-security-vulnerability)).

## Reporting a Security Vulnerability

GUN-101 treats security reports with the highest priority. **Do not open a public GitHub issue for a security vulnerability.** Instead, email the maintainer directly at **adityaraj1234@duck.com** with the subject prefix `[GUN101-SEC]`.

What we commit to:

- Acknowledgement of receipt within **48 hours**
- A fix timeline within **7 days**
- Coordinated public disclosure only after a patched release is available

The full process — supported versions, what is in and out of scope, how to structure a report, and how reporters are credited — is in [SECURITY.md](SECURITY.md).

## Project Documentation

- [Architecture](docs/ARCHITECTURE.md) — high-level design of the modules and data flow
- [Command-Line Reference](docs/CLI.md) — external interface, inputs, outputs, exit codes, formats
- [Upgrading](docs/UPGRADING.md) — how to upgrade and what changed between versions
- [Security Design](docs/SECURITY.md) — what the tool does and does not protect against
- [Threat Model](docs/THREAT_MODEL.md) — threat actors, mitigations, and scope
- [Assurance Case](docs/ASSURANCE_CASE.md) — argument that the security requirements are met
- [Security Review](docs/SECURITY_REVIEW.md) — documented security review of the current release
- [Releasing and verifying releases](docs/RELEASING.md) — how releases are signed and verified
- [Security Policy](SECURITY.md) — how to report vulnerabilities
- [Governance](GOVERNANCE.md) — roles, decision-making, and business continuity
- [Roadmap](ROADMAP.md) — what the project intends to do and not do over the next year
- [Contributing](CONTRIBUTING.md) — how to contribute and the required standards

## License

MIT License - see [LICENSE](LICENSE) file.

## Warning

This software is provided as-is without warranty. Use at your own risk. The author is not liable for any data loss or security breach resulting from the use or misuse of this software.

**Remember**: Encryption is only as strong as your password and your ability to keep the keyfile (if used) secure. No tool can protect against a compromised endpoint or a coerced user.