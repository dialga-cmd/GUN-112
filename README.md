# GUN-101

A simple, secure file encryption tool using **AES-256-GCM** and **Argon2id**.

## Overview

GUN-101 encrypts files with authenticated encryption, providing confidentiality and integrity. It supports two modes:

1. **Password-only**: Encryption key derived from password alone
2. **Password + keyfile**: Two-factor protection requiring both password and a separate keyfile

The design prioritizes correctness and transparency over complexity or marketing claims.

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

### Decrypt a file

```bash
gun101 decrypt secrets.pdf.gun101 --keyfile /path/to/keyfile
```
Decrypts to `secrets.pdf` (removes `.gun101` extension). Omit `--keyfile` for password-only mode.

**Password requirements**: Must be at least 10 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.

### Verify a keyfile fingerprint

```bash
gun101 keyfile-fingerprint /path/to/keyfile
```
Prints the SHA-256 fingerprint to confirm you have the correct keyfile.

## Command Reference

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

## Testing

Run the test suite with:

```bash
pytest tests/ -v
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Warning

This software is provided as-is without warranty. Use at your own risk. The author is not liable for any data loss or security breach resulting from the use or misuse of this software.

**Remember**: Encryption is only as strong as your password and your ability to keep the keyfile (if used) secure. No tool can protect against a compromised endpoint or a coerced user.