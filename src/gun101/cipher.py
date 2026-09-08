"""AES-256-GCM encryption and decryption."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config


def encrypt(plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        plaintext: The data to encrypt (must be bytes).
        key: The encryption key of length AES_KEY_LEN bytes.
        nonce: 12-byte nonce for encryption (must be unique for each key).
        associated_data: Optional additional data to authenticate but not encrypt.

    Returns:
        A tuple (ciphertext, tag) where:
            ciphertext: The encrypted data (same length as plaintext).
            tag: 16-byte authentication tag.

    Raises:
        ValueError: If key is not of correct length or nonce is not of correct length.

    Security note:
        AES-GCM provides authenticated encryption (confidentiality and integrity).
        It is resistant to padding oracle attacks and is standardized by NIST SP 800-38D.
    """
    if not isinstance(key, bytes) or len(key) != config.AES_KEY_LEN:
        raise ValueError(f"Key must be {config.AES_KEY_LEN} bytes")
    if not isinstance(nonce, bytes) or len(nonce) != config.AES_NONCE_LEN:
        raise ValueError(f"Nonce must be {config.AES_NONCE_LEN} bytes")
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("Associated data must be bytes")

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag concatenated
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = ciphertext_tag[:-16]
    tag = ciphertext_tag[-16:]
    return ciphertext, tag

def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt and authenticate ciphertext with AES-256-GCM.

    Args:
        nonce: 12-byte nonce used during encryption.
        ciphertext: The encrypted data.
        tag: 16-byte authentication tag.
        key: The decryption key of length AES_KEY_LEN bytes.
        associated_data: Optional additional data that was authenticated during encryption.

    Returns:
        The decrypted plaintext as bytes.

    Raises:
        ValueError: If decryption or authentication fails (for any reason).
    """
    if not isinstance(key, bytes) or len(key) != config.AES_KEY_LEN:
        raise ValueError(f"Key must be {config.AES_KEY_LEN} bytes")
    if not isinstance(nonce, bytes) or len(nonce) != config.AES_NONCE_LEN:
        raise ValueError(f"Nonce must be {config.AES_NONCE_LEN} bytes")
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes")
    if not isinstance(tag, bytes) or len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("Associated data must be bytes")

    aesgcm = AESGCM(key)
    try:
        # Combine ciphertext and tag for decryption
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
        return plaintext
    except Exception:
        # Any error (invalid tag, wrong key, etc.) results in a generic error
        raise ValueError("Decryption failed") from None
