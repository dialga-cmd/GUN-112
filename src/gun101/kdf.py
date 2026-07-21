"""Key derivation using Argon2id."""
import argon2.low_level
from . import config

def derive_key(password: str, salt: bytes, keyfile_bytes: bytes = None) -> bytes:
    """
    Derive a 256-bit AES key from a password using Argon2id.

    If keyfile_bytes is provided, it is appended to the encoded password
    before derivation, making the key dependent on both password and keyfile.

    Args:
        password: The user-provided password (non-empty string).
        salt: Random salt of length ARGON2_SALT_LEN bytes.
        keyfile_bytes: Optional keyfile content of length KEYFILE_LEN bytes.

    Returns:
        A 32-byte key suitable for AES-256-GCM.

    Raises:
        ValueError: If inputs are not of correct length or type.

    Security properties:
        - Argon2id is memory-hard, resisting GPU/ASIC attacks.
        - It uses data-independent memory access to resist side-channel attacks.
        - Winner of the Password Hashing Competition (2015).
        - Recommended by OWASP and NIST SP 800-63B.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) != config.ARGON2_SALT_LEN:
        raise ValueError(f"Salt must be {config.ARGON2_SALT_LEN} bytes")
    if keyfile_bytes is not None:
        if not isinstance(keyfile_bytes, bytes) or len(keyfile_bytes) != config.KEYFILE_LEN:
            raise ValueError(f"Keyfile must be {config.KEYFILE_LEN} bytes if provided")

    # Combine password and keyfile (if present) as UTF-8 bytes
    pwd_bytes = password.encode('utf-8')
    if keyfile_bytes is not None:
        pwd_bytes = pwd_bytes + keyfile_bytes
    return argon2.low_level.hash_secret_raw(
        secret=pwd_bytes,
        salt=salt,
        time_cost=config.ARGON2_TIME_COST,
        memory_cost=config.ARGON2_MEMORY_COST,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=config.ARGON2_HASH_LEN,
        type=argon2.low_level.Type.ID
    )