---
name: Security vulnerability report
about: Do NOT file public issues for security vulnerabilities
title: ""
labels: ""
assignees: ""
---

## STOP — please do not file a public issue

**If you have found a security vulnerability in GUN-101, do not open a public
issue on GitHub. Please email `adityaraj1234@duck.com` instead.**

Publicly disclosing a vulnerability before a fix is released puts every user of
the library at risk. Files encrypted with GUN-101 may be stored or shared for
years, and a premature disclosure tells attackers exactly how to break them —
often on systems whose owners are not even aware they depend on this software.

If you have merely found unusual but not obviously vulnerable behaviour, this
may instead be best filed as a **bug report** (using the bug report template)
or may already be a documented limitation in
[THREAT_MODEL.md](docs/THREAT_MODEL.md) or [SECURITY.md](docs/SECURITY.md).

## Private report format

When emailing `adityaraj1234@duck.com`, please structure your report as
follows. The more precise you can be, the faster it can be triaged:

**Affected component**: (e.g. key derivation in `kdf.py`, AES-GCM handling in
`cipher.py`, container parsing in `handler.py`, keyfile handling in
`keyfile.py`, CLI in `cli.py`)

**Description of the vulnerability**: (what is the flaw, and what security
property — confidentiality, integrity, authentication — does it violate?)

**Steps to reproduce**: (exact CLI commands, code snippets, or inputs needed to
demonstrate it, including the Python/library versions used)

**Potential impact**: (who is affected, what could an attacker achieve — e.g.
file disclosure, undetected tampering, brute-force weakening?)

**Suggested fix (optional)**: (if you have a proposed fix or mitigation, include
it)

**Disclosure preference**: (whether you consent to being credited, or prefer to
remain anonymous)

Publicly responsible disclosure is appreciated and will be handled with full
credit in the project's changelog and README acknowledgements unless you ask to
remain anonymous.

## Our commitment

- **Acknowledgement**: within **48 hours** of receiving the report.
- **Fix timeline**: communicated within **7 days**.
- **Coordination**: the fix and any advisory will be developed together with
  the reporter before coordination with the wider community, and disclosed only
  after a patched release is available.

Full details are in [SECURITY_POLICY.md](SECURITY_POLICY.md).