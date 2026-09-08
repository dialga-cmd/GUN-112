# Upgrading GUN-101

This document describes how to upgrade GUN-101 between versions, and which
interfaces changed. It is the upgrade-path documentation for the project.

## How to upgrade

GUN-101 is distributed on PyPI. Upgrade to the latest release with:

```bash
pip install --upgrade gun101
```

Upgrading the tool does **not** change the format of files you have already
encrypted. Encrypted files produced by older supported versions keep decrypting
after an upgrade (see [Backward compatibility](#backward-compatibility) below).

## Version history and upgrade path

### 2.0.x → 2.1.x

**Required action for users: none.** Existing v2.0 encrypted files continue to
decrypt with 2.1.x. New files are written in the v2.1 format, which binds the
cleartext header fields (protocol, version, keyfile flags) into the AES-GCM
associated data so header tampering is detected.

**Breaking interface change:** the `--password <value>` command-line argument
was removed in 2.1.0. Passwords must now be supplied either interactively (the
tool prompts with `Password: `) or via the `GUN101_PASSWORD` environment
variable. This change prevents the password from appearing in process listings
and shell history.

If you scripted GUN-101 with `--password`, update your scripts to set
`GUN101_PASSWORD` instead, and read the trade-offs in
[docs/SECURITY.md](SECURITY.md):

```bash
# Before (2.0.x)
gun101 encrypt file.txt --password 'S3cret!Pass1'

# After (2.1+)
GUN101_PASSWORD='S3cret!Pass1' gun101 encrypt file.txt
```

Nothing else in the CLI changed: `encrypt`, `decrypt`, `generate-keyfile`, and
`keyfile-fingerprint` keep the same arguments and behaviour.

### Earlier versions (< 2.0)

Versions before 2.0 are end-of-life (see [SECURITY.md](SECURITY.md)) and are
not maintained. If you use a pre-2.0 container, re-encrypt the files with the
current release: decrypt with the old version, then encrypt with the new one.

## Backward compatibility

The container format is versioned. GUN-101 always encrypts with the current
version (2.1) and decrypts containers written by the current and immediately
earlier versions:

| Container version | Encrypts (writes) | Decrypts (reads) |
|-------------------|-------------------|------------------|
| 2.1 (current)     | Yes               | Yes              |
| 2.0 (legacy)      | No                | Yes              |

This guarantees that upgrading the tool never locks you out of your existing
encrypted files.

## Supported-version policy

Security fixes are released for the current release line and (for critical
fixes only) the immediately preceding minor line. See the supported-versions
table in [SECURITY.md](SECURITY.md) and the [CHANGELOG](CHANGELOG.md) for what
changed in each release.