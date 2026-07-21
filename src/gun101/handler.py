"""High-level encryption and decryption handler."""
import json
import base64
import os
import string
from . import config
from . import kdf
from . import cipher
from . import keyfile


def validate_password(password: str) -> None:
    """
    Validate password strength.

    Args:
        password: The password to validate.

    Raises:
        ValueError: If the password does not meet strength requirements.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(c in string.punctuation for c in password):
        raise ValueError("Password must contain at least one special character")


def encrypt_file(file_data: bytes, password: str, keyfile_path: str = None) -> bytes:
    """
    Encrypt file data with optional keyfile for two-factor protection.

    Args:
        file_data: The file content to encrypt (bytes).
        password: The user password (must be at least 10 characters with uppercase, lowercase, digit, and special character).
        keyfile_path: Optional path to a keyfile for two-factor mode.

    Returns:
        Encrypted container as UTF-8 encoded JSON bytes.

    Steps:
        1. Validate inputs.
        2. Generate random salt.
        3. Load keyfile if provided.
        4. Derive encryption key using Argon2id.
        5. Encrypt data with AES-256-GCM.
        6. Wipe key from memory.
        7. Build JSON container with metadata.
    """
    # Input validation
    if not isinstance(file_data, bytes):
        raise ValueError("File data must be bytes")
    validate_password(password)

    # Step 2: Generate salt
    salt = os.urandom(config.ARGON2_SALT_LEN)

    # Step 3: Load keyfile if provided
    keyfile_bytes = None
    if keyfile_path is not None:
        keyfile_bytes = keyfile.load_keyfile(keyfile_path)

    # Step 4: Derive key
    key = kdf.derive_key(password, salt, keyfile_bytes)

    # Step 5: Encrypt
    nonce, ciphertext, tag = cipher.encrypt(file_data, key)

    # Step 6: Wipe key from memory (overwrite with zeros and delete reference)
    key = bytes(config.AES_KEY_LEN)  # Overwrite with zeros
    del key

    # Step 7: Build container
    container = {
        "protocol": config.PROTOCOL,
        "version": config.VERSION,
        "keyfile_required": keyfile_path is not None,
        "keyfile_fingerprint": keyfile.keyfile_fingerprint(keyfile_bytes) if keyfile_bytes else None,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }
    return json.dumps(container).encode('utf-8')


def decrypt_file(container_data: bytes, password: str, keyfile_path: str = None) -> bytes:
    """
    Decrypt container data with optional keyfile.

    Args:
        container_data: The encrypted container (JSON bytes).
        password: The user password (must be at least 10 characters with uppercase, lowercase, digit, and special character).
        keyfile_path: Optional path to keyfile (required if container indicates keyfile_required).

    Returns:
        Decrypted file data as bytes.

    Raises:
        ValueError: For any error (malformed container, wrong password, missing/wrong keyfile, etc.).
    """
    # Validate password
    validate_password(password)

    # Step 1: Parse JSON
    try:
        container = json.loads(container_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Invalid container format")

    # Step 2: Verify protocol and version
    if container.get("protocol") != config.PROTOCOL:
        raise ValueError(f"Unsupported protocol: {container.get('protocol')}")
    if container.get("version") != config.VERSION:
        raise ValueError(f"Unsupported version: {container.get('version')}")

    # Step 3: Check if keyfile is required
    keyfile_required = container.get("keyfile_required", False)
    if keyfile_required and keyfile_path is None:
        raise ValueError("This file requires a key file. Use --keyfile <path>")

    # Step 4: If keyfile provided, verify fingerprint
    keyfile_bytes = None
    if keyfile_path is not None:
        keyfile_bytes = keyfile.load_keyfile(keyfile_path)
        expected_fingerprint = container.get("keyfile_fingerprint")
        if expected_fingerprint is None:
            raise ValueError("Container does not contain a keyfile fingerprint")
        actual_fingerprint = keyfile.keyfile_fingerprint(keyfile_bytes)
        if actual_fingerprint != expected_fingerprint:
            raise ValueError("Wrong key file.")

    # Step 5: Decode salt, nonce, ciphertext, tag
    try:
        salt = base64.b64decode(container["salt"])
        nonce = base64.b64decode(container["nonce"])
        ciphertext = base64.b64decode(container["ciphertext"])
        tag = base64.b64decode(container["tag"])
    except (KeyError, ValueError):
        raise ValueError("Container missing required fields")

    # Step 6: Derive key
    key = kdf.derive_key(password, salt, keyfile_bytes)

    # Step 7: Decrypt and wipe key on any outcome
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, tag, key)
    except ValueError as e:
        # Wipe key before re-raising
        key = bytes(config.AES_KEY_LEN)
        del key
        raise ValueError("Decryption failed: wrong password or corrupted file.") from e
    finally:
        # Ensure key is wiped even if decryption succeeds
        key = bytes(config.AES_KEY_LEN)
        del key

    return plaintext