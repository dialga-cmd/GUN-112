## Description of the change

A clear and concise description of what this PR changes and why. Link any
related issue (e.g. `Closes #12`).

## Type of change

Check all that apply:

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Security improvement
- [ ] Test addition
- [ ] Performance improvement

## Security review checklist

This is a cryptographic library. Reviewers will not merge a PR that fails any
of these checks.

- [ ] This change does not reduce Argon2id `time_cost`, `memory_cost`, or
      `parallelism`
- [ ] This change does not reduce AES key length or nonce length
- [ ] This change does not store the encryption key in plaintext on disk
- [ ] If this change touches key derivation or encryption logic, I have added
      a written justification in this PR description (see below)
- [ ] All new code has type hints and docstrings
- [ ] I have added tests for any new functionality — including both a positive
      and a negative test for any new security-affecting function
- [ ] I have run `pytest tests/ -v` and all tests pass
- [ ] I have read CONTRIBUTING.md

## Cryptographic justification (required for security-relevant changes)

If this PR touches key derivation (`kdf.py`), encryption/decryption
(`cipher.py`, `handler.py`), or keyfile handling (`keyfile.py`), explain the
cryptographic reasoning here: what property is preserved or improved, which
attack it addresses, and why the approach is sound with respect to the
guarantees in `docs/SECURITY.md` and `docs/THREAT_MODEL.md`.

## How was this tested?

Describe the environment and steps used to verify the change:

```bash
pytest tests/ -v
```

## Additional context

Anything else reviewers should know: platform-specific behaviour, dependency
changes, performance measurements, or documentation updates.