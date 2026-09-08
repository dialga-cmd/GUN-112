---
name: Bug report
about: Report a bug or unexpected behaviour in GUN-101
title: "[Bug] Short description of the problem"
labels: bug
assignees: ""
---

## Description

A clear and concise description of the bug you are seeing.

## Steps to reproduce

Include the exact CLI command or a minimal code snippet. If you used the
library API, show the call — including your password and keyfile handling if
relevant.

```bash
# example
gun101 encrypt secrets.pdf --keyfile /path/to/keyfile
```

```python
# or a library example
from gun101 import handler
handler.decrypt_file(container, "P@ssw0rd!Abc", "/path/to/keyfile")
```

## Expected behaviour

What did you expect to happen?

## Actual behaviour

What actually happened? Include the full, exact error message and traceback if
there is one.

```
(paste the exact error output here)
```

## Environment

- **OS**: (e.g. Ubuntu 24.04, Windows 11, macOS 14)
- **Python version**: (e.g. 3.12.3 — run `python --version`)
- **Library version**: (run `pip show gun101` and paste the Version line)
- **argon2-cffi version**: (run `pip show argon2-cffi`)
- **cryptography version**: (run `pip show cryptography`)

## Additional context

- Are you using password-only mode or password + keyfile mode?
- Was the file encrypted with an older GUN-101 version? (v2.0 containers are
  supported; this determines whether the issue is format-related)
- Anything else relevant: file size, how the output path was chosen, whether
  symlinks were involved, etc.

## Checklist

- [ ] I have checked that this is not a known limitation documented in
  `THREAT_MODEL.md` or `SECURITY.md`.
- [ ] I have searched the existing issues and this is not a duplicate.
- [ ] I am NOT reporting a security vulnerability (if I am, I will report
  it privately to adityaraj1234@duck.com instead of opening this issue).