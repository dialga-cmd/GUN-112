# GUN-101 Roadmap

This roadmap describes what GUN-101 intends to do — and explicitly not do — over
the next year. It is a living document; items may be reordered based on
feedback, and anything here may evolve as issues are discussed.

Last updated: 2026-09-09. Current release: 2.1.2.

## Goals for the next year

### Completed

- **`gun101 info` subcommand.** Inspect program and container configuration
  (protocol, version, Argon2 parameters, library versions) without decrypting.
- **Argon2id parameter benchmarking.** A repeatable benchmark script
  (`scripts/benchmark_kdf.py`) so that any future parameter changes are
  justified with measured time and memory numbers.
- **Fuzzing harness.** Hypothesis-based property fuzz tests for container
  parsing (`tests/test_fuzz_parser.py`) targeting `decrypt_file`.

### Near term (2–3 months)

- **Co-maintainer for the project.** Recruit and onboard a second maintainer so
  the bus factor reaches 2 and releases can be cut if the current maintainer is
  unavailable (see [GOVERNANCE.md](GOVERNANCE.md)).
- **Windows file-permission support for keyfiles.** `os.chmod(path, 0o600)` is
  POSIX-only; add correct handling on Windows (NTFS ACLs or a documented,
  tested fallback).

### Medium term (3–6 months)

- **Entropy-based password strength check.** Integrate a well-audited strength
  checker (e.g. `zxcvbn`) as an optional check on top of the existing
  composition policy.

### Longer term (6–12 months)

- **Reproducible/repeatable builds.** Verify that `python -m build` produces
  byte-identical wheels from the same source, and document the process.
- **Independent security review.** Commission or organize a security review of
  the key-derivation, encryption, and container-parsing paths by someone other
  than the maintainer.
- **Dependency policy.** Continue pinning dependencies with verified hashes in
  `requirements.lock` and keep the automated dependency-vulnerability audit
  (`pip-audit`) in CI.

## Out of scope (explicitly not doing)

- **Hand-rolled cryptography.** All crypto will continue to come from the
  well-audited `cryptography` and `argon2-cffi` libraries.
- **Network/key-exchange features.** GUN-101 is an offline file-encryption tool.
  We will not add key agreement, message exchange, or forward secrecy — those
  would be a different product and a different threat model.
- **Reducing security parameters.** Argon2id and AES parameters will never be
  weakened; changes are welcome only if they strengthen the defaults.
- **Password storage / authentication service.** GUN-101 derives keys from
  passwords; it does not and will not store passwords for user authentication.
- **New encryption primitives:** No replacement or extension of AES-256-GCM or
  Argon2id without an explicit, defensible reason.

## How to influence this roadmap

Open an issue or discussion. Real usage reports, failure reports, and requests
with concrete security reasoning are the most valuable input. See
`CONTRIBUTING.md` for how to contribute.