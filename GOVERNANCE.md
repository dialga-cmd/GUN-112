# GUN-101 Project Governance

This document defines how GUN-101 is governed: how decisions are made, what
roles exist, and how the project continues to operate if a maintainer is
unavailable.

## Project status

GUN-101 is a single-maintainer project. Governance is intentionally light
weight so that security fixes can be shipped quickly, while remaining open and
transparent so that the project can grow.

## Roles and responsibilities

### Maintainer

- Owns administrative access to the repository, the PyPI project, and any
  continuous-integration configuration.
- Merges pull requests and cuts releases (tags, version bumps, PyPI uploads).
- Triages and responds to issues, including security reports.
- Ultimately responsible for the correctness and safety of the cryptographic
  code and for upholding the security rules in `CONTRIBUTING.md`.
- May be reached at `adityaraj1234@duck.com`.

Current maintainer: **Aditya Raj**.

### Contributors

- Anyone who reports a bug, opens a pull request, or participates in
  discussions.
- Expected to follow `CONTRIBUTING.md`, especially the security-specific rules.
- No repository or release permissions unless explicitly granted by the
  maintainer.

### Security reporters

- Anyone reporting a vulnerability privately per `SECURITY.md`. Reports are
  acknowledged within 48 hours.

### Onboarding to maintainer

- Anyone with a consistent, high-quality contribution history may be granted
  maintainer access. The current maintainer makes this decision, and it is
  announced publicly in the repository so the community can object if needed.
- New maintainers are expected to read `CONTRIBUTING.md` and
  `docs/SECURITY.md` and to respect the non-negotiable security parameters.

## Decision-making

- **Everyday decisions** (bug fixes, documentation, test improvements) are made
  by the maintainer directly through normal code review.
- **Security-relevant decisions** (anything touching `kdf.py`, `cipher.py`,
  `handler.py`, or `keyfile.py`) follow the process in `CONTRIBUTING.md`,
  including a written cryptographic justification.
- **Large or controversial changes** (e.g., changing the container format,
  adding dependencies, or changing security parameters) are proposed in a
  public issue, discussed, and merged only after a review period. Where more
  than one maintainer exists, consensus is required; if consensus cannot be
  reached, a simple majority of maintainers decides.
- Parameter changes to Argon2id or AES follow the guidance in `CONTRIBUTING.md`
  and must never weaken the defaults.

## Business continuity

The project must be able to continue with minimal interruption if the
maintainer becomes unavailable. We aim to make the project as functional as
possible without the maintainer, and to make handover practical:

- **Everything is public.** All source, history, issues, and CI configuration
  live in the public GitHub repository and are mirrored in normal tooling.
  Nothing is locked in a private machine.
- **Release access.** The PyPI publishing workflow uses OpenID Connect trusted
  publishing (`pip-audit`, `.github/workflows/publish.yml`), so ownership of the
  GitHub repository is the effective key to publishing. A successor with
  repository ownership can publish releases without secrets.
- **Handover plan.** In case of prolonged unavailability of the current
  maintainer, a contributor with a demonstrated history may be granted
  repository ownership by the hosting platform through its normal transfer
  process. All necessary access (code, issue tracker, CI, PyPI) is inherited
  from repository ownership and therefore continues to work.
- **Goal:** bring in a second maintainer that all releases can be cut
  independently, so that issues can be created, closed, changes merged, and
  versions released within a week of losing any single person.

Contributors who are interested in becoming a co-maintainer should open an
issue or contact the maintainer.

## Code of conduct

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). The maintainer is responsible for
enforcing it.