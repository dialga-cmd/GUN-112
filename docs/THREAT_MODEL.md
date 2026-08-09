# GUN-101 Threat Model

## Overview

This document outlines the threats considered in the design of GUN-101 and how the system addresses (or does not address) them. It is intended to help users understand the security guarantees and limitations of the software. The library enforces a password policy requiring a minimum length of 10 characters with uppercase, lowercase, digit, and special character.

## Assets

- Plaintext file contents (confidentiality)
- User password (secrecy)
- Keyfile contents (when used for two-factor protection)

## Trust Assumptions

- The execution environment is trusted (no malware, rootkits, or hardware keyloggers)
- The user is responsible for choosing a strong password; the library enforces a minimum password standard to resist brute-force attacks
- When two-factor mode is used, the keyfile is stored on a separate, trusted device
- The encrypted container may be stored or transmitted over untrusted channels

## Threat Actors and Mitigations

### 1. Passive Attacker (File Only)

**Capabilities:**
- Obtains the encrypted `.gun101` file (e.g., via backup theft, network interception, cloud storage breach)
- Attempts offline brute-force or dictionary attacks
- Does not have the ability to execute code on the victim's machine
- No access to password or keyfile (if used)

**Mitigations:**
- AES-256-GCM with a random 12-byte nonce provides confidentiality assuming key secrecy
- Key derived via Argon2id with parameters:
  - Time cost: 4
  - Memory: 256 MiB
  - Parallelism: 4 lanes
  - Salt: 32 bytes random
  - Hash length: 32 bytes
- Argon2id’s memory hardness raises the cost of GPU/ASIC attacks
- Salt prevents rainbow table attacks across different files
- Without the keyfile (if used), attacker lacks necessary input to key derivation

**Residual Risk:** Security depends on password entropy. The enforced password policy increases the cost of brute-force attacks, but users should still choose sufficiently strong passwords.

### 2. Attacker with Password but No Keyfile (Two-Factor Mode Only)

**Capabilities:**
- Knows the user’s password (e.g., via shoulder surfing, leak from another site)
- Has obtained the encrypted file
- Does not possess the keyfile

**Mitigations:**
- Encryption key is derived from both password and keyfile via concatenation before Argon2id
- Without the keyfile, the correct encryption key cannot be computed
- Attempting to decrypt with password alone yields incorrect key, leading to decryption failure (authentication tag mismatch)

**Required Condition:** The keyfile must be stored separately from the encrypted file. If both are compromised, this threat model does not apply.

**Residual Risk:** None, assuming keyfile secrecy is maintained.

### 3. Attacker with Both File and Keyfile

**Capabilities:**
- Possesses the encrypted `.gun101` file
- Possesses the keyfile (if used)
- May or may not know the password

**Mitigations:**
- Security then relies solely on password strength
- Argon2id still provides brute-force resistance via memory and time costs
- Salt unique per file prevents amortized attacks across multiple files

**Residual Risk:** Protects only against brute-force attacks; does not provide two-factor protection in this scenario. User must rely on strong password, noting that the library enforces a minimum password standard.

### 4. Attacker with Local Machine Access (Malware)

**Capabilities:**
- Can execute arbitrary code on the encryption/decryption host
- Can install keyloggers, screen scrapers, memory dumpers
- Can capture password during input
- Can read keyfile from disk if present
- Can intercept plaintext before encryption or after decryption

**Mitigations:** None. This threat is explicitly out of scope for this mode.

**Required Mitigation:** Users must maintain a secure, trusted computing base (e.g., air-gapped machine, antivirus, behavioral monitoring).

### 5. Weak Password

**Capabilities:**
- Can guess or brute-force low-entropy passwords (e.g., dictionary attacks, credential stuffing)
- Benefits from unlimited guess attempts (no artificial rate limiting to avoid denial-of-service)

**Mitigations:**
- Argon2id increases cost per guess via memory and time parameters
- The library enforces a minimum password length of 10 characters requiring uppercase, lowercase, digit, and special character, significantly increasing the entropy required for brute-force attacks
- However, users should still avoid predictable passwords

**Residual Risk:** Users are responsible for choosing passwords with sufficient entropy to resist brute-force attacks given the configured Argon2id parameters and the enforced policy. A randomly generated password meeting the policy is recommended.

### 6. Active Attacker (Tampering)

**Capabilities:**
- Modifies the ciphertext, nonce, auth tag, or other parts of the container
- Attempts to induce decryption of incorrect plaintext or bypass authentication

**Mitigations:**
- AES-256-GCM provides integrity: any modification to the container (including ciphertext, nonce, tag, or header fields) results in decryption failure. Header fields (protocol, version, etc.) are authenticated as associated data in the v2.1 format.
- Authentication tag verified before returning plaintext.
- On failure, library returns a generic "Decryption failed" error to avoid oracle attacks.

**Residual Risk:** None. Tampering is detected with overwhelming probability.

### 7. Side-Channel Attacks

**Capabilities:**
- Attacker observes timing, power, electromagnetic leaks, or cache usage during encryption/decryption
- Attempts to derive secret keys

**Mitigations:**
- Argon2id is designed to resist side-channel attacks via data-independent memory access
- However, the Python implementation (argon2-cffi) may still leak some timing information
- AES-NI usage in cryptography backend reduces timing variability, but not guaranteed

**Residual Risk:** Possible leakage of key information via advanced side-channels. Users requiring resistance to such attacks should use hardware security modules or specialized libraries.

## Considerations for Two-Factor Mode

- The keyfile must be stored on a separate physical device (e.g., USB stick) from the encrypted file
- Loss of the keyfile results in permanent data loss (even with password)
- The keyfile should be backed up in a secure location (e.g., encrypted backup, split via Shamir’s Secret Sharing)
- The keyfile itself is not encrypted; its security relies on physical separation

## Recommendations

1. **Password Choice:** Use a password that meets the library's requirements (minimum 10 characters with uppercase, lowercase, digit, and special character). For higher security, consider a randomly generated passphrase of 14+ characters meeting these criteria.
2. **Keyfile Storage:** Keep on an encrypted USB drive or offline storage. Never store in the same location as the encrypted file.
3. **Backups:** Maintain encrypted backups of both the encrypted file (trivial) and the keyfile (requires separate secure backup).
4. **Recovery:** There is no backdoor or recovery mechanism. Losing password or keyfile means permanent data loss.
5. **Post-Use:** Consider wiping temporary files and swap space after decryption if handling highly sensitive data.

## Out of Scope

- Protection against compromised endpoints
- Protection against rubber-hose cryptanalysis (coercion)
- Protection against temp files or swap leakage
- Protection against timing attacks in multi-tenant environments
- Denial-of-service resistance (by design, we do not rate-limit password attempts)

## Conclusion

GUN-101 provides strong confidentiality and integrity for stored files when used with a password meeting the enforced policy and, optionally, a physically separate keyfile. Its security relies on well-vetted cryptographic primitives and honest usage. Users must understand and accept the limitations, particularly regarding endpoint security and password strength.