# GUN-101 Architecture

This document describes the high-level design (architecture) of GUN-101 — the
modules, their responsibilities, and the data flow through the system.

## Overview

GUN-101 is a Python command-line tool and library that encrypts and decrypts
files using authenticated encryption. It is structured as a small number of
single-responsibility modules under `src/gun101/`, all of which depend on the
well-audited `cryptography` and `argon2-cffi` libraries. No cryptographic
primitives are implemented from scratch.

```
+----------------------------------------------------------+
|                          cli.py                          |
|   argparse subcommands: encrypt, decrypt,                 |
|   generate-keyfile, keyfile-fingerprint; password input;  |
|   path safety                                             |
+----------------------------+-----------------------------+
                             | calls high-level API
                             v
+----------------------------------------------------------+
|                        handler.py                         |
|   encrypt_file()/decrypt_file(): container (de)serialize, |
|   header construction, v2.0/v2.1 handling, fingerprint    |
|   verification, password policy                           |
+--------+----------------+-----------------+--------------+
         |                |                 |
         v                v                 v
+----------------+ +-----------------+ +------------------+
|    kdf.py      | |    cipher.py    | |    keyfile.py    |
| Argon2id key   | | AES-256-GCM     | | keyfile bytes,   |
| derivation     | | encrypt/decrypt | | generation,      |
| (password +    | | with associated | | SHA-256          |
| optional       | | data            | | fingerprint      |
| keyfile)       | |                 | |                  |
+----------------+ +-----------------+ +------------------+
         |                |                 |
         v                v                 v
+----------------------------------------------------------+
|                        config.py                          |
|   PROTOCOL, VERSION, Argon2id/AES/keyfile parameters      |
+----------------------------------------------------------+
```

## Modules

### `cli.py` — command-line interface

- Parses arguments for the four subcommands (`encrypt`, `decrypt`,
  `generate-keyfile`, `keyfile-fingerprint`) with `argparse`.
- Obtains the password either from the `GUN101_PASSWORD` environment variable
  (with a warning) or through `getpass.getpass()`.
- Enforces path safety via `safe_open_write()` before writing any output:
  rejects symlinks and paths that escape the current working directory.
- Converts library-layer failures (`ValueError`/`OSError`) into exit code 1
  with a message on stderr.

### `handler.py` — high-level orchestration

- `encrypt_file()`: validates inputs and password policy, generates a fresh
  random salt and nonce, loads the optional keyfile, derives the key, encrypts
  with the JSON header as GCM associated data, and serializes the container.
- `decrypt_file()`: parses the container, checks protocol and supported
  versions (`2.0`, `2.1`), enforces keyfile requirements and fingerprint
  matching (constant-time), then decrypts. Every failure — malformed container,
  wrong password, wrong/missing keyfile, or GCM tag failure — surfaces as the
  generic `ValueError("Decryption failed")` to prevent oracle attacks.

### `kdf.py` — key derivation

- `derive_key()`: runs Argon2id over the UTF-8 password bytes, with the
  optional keyfile bytes appended, producing a 32-byte key.

### `cipher.py` — authenticated encryption

- `encrypt()` / `decrypt()`: thin wrappers around
  `cryptography.hazmat.primitives.ciphers.aead.AESGCM` with strict parameter
  validation (32-byte key, 12-byte nonce, bytes inputs).

### `keyfile.py` — two-factor key material

- `generate_keyfile()`: writes 32 random bytes with `0600` permissions,
  refusing to overwrite existing files.
- `load_keyfile()`: reads and validates keyfile length.
- `keyfile_fingerprint()`: SHA-256 hex digest of the keyfile bytes.

### `config.py` — parameters

- Single source of truth for the protocol name, container version, and all
  cryptographic parameters (Argon2id time/memory/parallelism/hash/salt lengths,
  AES key/nonce lengths, keyfile length). These are intentionally not
  configurable at runtime; see `CONTRIBUTING.md`.

## Data flow

### Encryption

1. Read file bytes.
2. Derive a fresh 32-byte salt (`os.urandom`) and 12-byte nonce.
3. Optionally load keyfile bytes.
4. `kdf.derive_key(password, salt, keyfile_bytes)` → 32-byte key.
5. Build the JSON header (protocol, version, keyfile flags/fingerprint, salt,
   nonce) and serialise it compactly with sorted keys.
6. `cipher.encrypt(data, key, nonce, header_bytes)` → ciphertext + 16-byte tag
   (header authenticated as AAD).
7. Serialize header + ciphertext + tag as a UTF-8 JSON document (the `.gun101`
   container).

### Decryption

1. Parse the container; reject if protocol is not `GUN-101` or the version is
   not `2.0`/`2.1`.
2. If the container requires a keyfile, load it and verify its stored SHA-256
   fingerprint with `hmac.compare_digest`.
3. Re-derive the key and decrypt. For `2.1`, reconstruct the header (all fields
   except `ciphertext`/`tag`) and pass it as associated data; for legacy `2.0`,
   decrypt without AAD.
4. Any GCM authentication failure → generic `Decryption failed`.

## Format compatibility

- v2.1 (current): header fields are authenticated as associated data; decrypt
  rejects tampered headers.
- v2.0 (legacy): supported for decryption only; new files are always written
  as v2.1.

## Non-goals

- Executable binaries or native code.
- Network communication, key exchange, or forward secrecy.
- Storing or hashing passwords for user authentication.
- Guaranteed memory wiping (documented limitation of Python).