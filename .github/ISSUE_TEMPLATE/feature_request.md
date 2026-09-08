---
name: Feature request
about: Suggest a new feature or improvement for GUN-101
title: "[Feature] Short description of the request"
labels: enhancement
assignees: ""
---

## Description of the feature

A clear and concise description of what you want added or changed.

## Problem it solves / use case it enables

What problem does this solve, or what use case does it enable? Please be
specific — for example: "I want to encrypt a directory of documents in one
command" or "I want to verify I have the right keyfile before decrypting".

## Proposed implementation approach (optional but encouraged)

If you have an idea for how it could be implemented, describe it here. Note
which module it would touch in `src/gun101/` (e.g. `cli.py`, `handler.py`,
`keyfile.py`, `config.py`) and whether it changes the container format.

## Security implications

Does this feature touch **key derivation**, **encryption**, or **decryption**
logic?

- [ ] No
- [ ] Yes

If it touches any of these, please provide a cryptographic justification for
why the change is sound. See [SECURITY.md](docs/SECURITY.md) and
[THREAT_MODEL.md](docs/THREAT_MODEL.md) for the current guarantees.

## Alternatives considered

What alternatives did you consider, and why did you choose this one? If a
feature already exists that partially covers this, note the gap.

## Checklist

- [ ] I have read `SECURITY.md` and this feature does not weaken any existing
  security guarantee.
- [ ] I have searched the existing issues and this is not a duplicate.