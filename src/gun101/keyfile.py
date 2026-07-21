"""Keyfile handling for two-factor protection."""
import os
import hashlib
from . import config

def generate_keyfile(path: str) -> None:
    """
    Generate a cryptographically random keyfile.

    Args:
        path: The filesystem path where the keyfile will be written.

    Raises:
        ValueError: If a file already exists at the given path.

    Side effects:
        Creates a file at `path` with 0o600 permissions containing
        KEYFILE_LEN random bytes.
    """
    if os.path.exists(path):
        raise ValueError(f"Key file already exists at {path}. "
                         "Delete it manually if you intend to replace it.")
    keyfile_bytes = os.urandom(config.KEYFILE_LEN)
    with open(path, 'wb') as f:
        f.write(keyfile_bytes)
    # Restrict permissions to owner read/write only
    os.chmod(path, 0o600)

def load_keyfile(path: str) -> bytes:
    """
    Load a keyfile from disk.

    Args:
        path: Path to the keyfile.

    Returns:
        The keyfile bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not exactly KEYFILE_LEN bytes.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file not found: {path}")
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != config.KEYFILE_LEN:
        raise ValueError(f"Key file must be {config.KEYFILE_LEN} bytes long")
    return data

def keyfile_fingerprint(keyfile_bytes: bytes) -> str:
    """
    Compute a SHA-256 fingerprint of the keyfile bytes.

    Args:
        keyfile_bytes: The keyfile bytes (must be KEYFILE_LEN bytes).

    Returns:
        A hexadecimal string of length 64 (SHA-256 digest).
    """
    if not isinstance(keyfile_bytes, bytes) or len(keyfile_bytes) != config.KEYFILE_LEN:
        raise ValueError(f"Keyfile must be {config.KEYFILE_LEN} bytes")
    return hashlib.sha256(keyfile_bytes).hexdigest()