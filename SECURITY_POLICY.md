# Security Policy

GUN-101 is a cryptographic library: files are encrypted with AES-256-GCM and
key material is derived with Argon2id. Security is the primary design concern,
and security issues are treated with the highest priority. This document
describes which versions are supported, how to report a vulnerability, what we
are and are not responsible for, and how reporters are credited.

## Supported versions

Security fixes are only ever released for the most recent major/minor line,
with limited backporting to the immediately preceding minor release. Encryption
tools outlive individual releases — update to a supported version promptly.

| Version  | Support status                                                          |
| -------- | ---------------------------------------------------------------------- |
| 2.1.x    | Fully supported. Receives security fixes in new patch releases.        |
| 2.0.x    | Maintained for critical security fixes only; users should upgrade.     |
| < 2.0    | End of life. No security fixes. Upgrade required.                      |

The current release, **2.1.0**, is fully supported.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Please email the maintainer directly at **adityaraj1234@duck.com**.
Publicly filing a vulnerability before a fix exists warns attackers that there
is something to exploit, and the library's encrypted output may remain in
circulation for years — a premature disclosure harms users who cannot quickly
update.

Use a plain-text email with the subject prefix `[GUN101-SEC]`. Include as much
of the following as you can:

- The affected component (key derivation in `kdf.py`, AES-GCM handling in
  `cipher.py`, container parsing in `handler.py`, keyfile handling in
  `keyfile.py`, or the CLI in `cli.py`).
- A description of the vulnerability and which security property it violates
  (confidentiality, integrity, or authentication).
- Exact reproduction steps: CLI commands or code snippets, and the Python,
  `argon2-cffi`, and `cryptography` versions involved.
- The potential impact on users and the conditions required to exploit it.
- A suggested fix or mitigation, if you have one (optional).
- Your disclosure preference (see [Credit](#credit) below).

If you prefer, you may encrypt your report with the maintainer's PGP key —
request the fingerprint by email before sending anything sensitive.

## Response timeline

We commit to the following response times:

| Step                            | Commitment                    |
| ------------------------------- | ----------------------------- |
| Acknowledgement of receipt      | Within **48 hours**           |
| Fix timeline communicated       | Within **7 days**             |
| Coordinated public disclosure   | After a patched release is available |

If more time is needed to fully fix or assess a report, you will be told why
and given an updated estimate. Reports receive high priority by default; reports
with a clear exploit path or mass impact are dealt with before everything else.

## Coordinated disclosure

- We will work with the reporter to confirm the issue and develop a fix.
- A fixed release is prepared, and only then is the vulnerability disclosed
  publicly with an advisory and changelog entry.
- Reasonable embargo periods for coordination are respected where an upstream
  or ecosystem advisory is involved.
- We will never disclose a vulnerability before a patched release exists except
  with the reporter's explicit consent.

## Credit

Reporters who responsibly disclose a vulnerability will be credited in the
CHANGELOG and in the README acknowledgements section, unless they request
anonymity. Anonymous reporting is fully respected and does not slow down
handling of the report. Duplicate reports are credited to the first reporter in
each case.

## Scope

### In scope

The library's own code and threat surface, as implemented in `src/gun101/`:

- Key derivation (`kdf.py`) — Argon2id parameters and input handling.
- Encryption and decryption (`cipher.py`, `handler.py`) — AES-256-GCM,
  associated-data handling, container parsing, and password policy.
- Keyfile handling (`keyfile.py`) — generation, validation, and fingerprint
  comparison.
- The command-line interface (`cli.py`) — argument handling, path safety, and
  password input handling.
- The `.gun101` container format itself.

The full and authoritative statement of the threat model, assets, trust
assumptions, and out-of-scope items is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
Please read it before assessing whether a finding is a genuine vulnerability.

### Out of scope

GUN-101 explicitly does **not** protect against, and therefore does not treat
as vulnerabilities, the items listed as out of scope in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), including:

- Malware, keyloggers, or other compromise of the machine running
  encrypt/decrypt.
- Side-channel attacks (timing, power, cache) beyond what Argon2id's
  data-independent memory access mitigates.
- Rubber-hose cryptanalysis (physical coercion).
- Leakage via temporary files, swap space, or process memory on the host.
- Weak passwords — GUN-101 enforces a minimum password standard (at least 10
  characters with upper/lowercase, digit, and special character) but cannot
  compensate for a user choosing a predictable password.
- Both the encrypted file and the keyfile being stolen together in two-factor
  mode (security then reduces to password strength).
- Future cryptographic breaks of AES-256-GCM or Argon2id.

Implementation shortcomings of well-audited dependencies (`argon2-cffi`,
`cryptography`) should be reported to those projects, not this one, unless they
can be shown to be triggered by GUN-101's specific usage.

## General security advice

- Choose a strong password meeting the enforced policy; a randomly generated
  password of 14+ characters is recommended.
- In two-factor mode, keep the keyfile on a separate physical device (e.g. a
  USB drive) from the encrypted files, and back it up securely. Losing either
  the password or the keyfile means permanent data loss — there is no backdoor.
- Encrypt on machines you trust. No tool can protect a compromised endpoint.