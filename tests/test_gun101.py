"""Test suite for GUN-101."""
import base64
import json
import os
import tempfile
import pytest
from src.gun101 import handler, keyfile, kdf, cipher, config

# Strong passwords for testing
STRONG_PASSWORD = "Str0ngP@ssw0rd!"  # 13 chars: upper, lower, digit, special
STRONG_PASSWORD_2 = "P@ssw0rd12!Xyz"  # 13 chars: different
WEAK_PASSWORD_SHORT = "weak"  # too short
WEAK_PASSWORD_NO_UPPER = "lowercase123!"  # no uppercase
WEAK_PASSWORD_NO_LOWER = "UPPERCASE123!"  # no lowercase
WEAK_PASSWORD_NO_DIGIT = "NoDigit!!!!"  # no digit
WEAK_PASSWORD_NO_SPECIAL = "NoSpecial123"  # no special

# Helper functions for testing
def encrypt_decrypt_cycle(data, password, keyfile_path=None):
    """Helper to encrypt and then decrypt data."""
    container = handler.encrypt_file(data, password, keyfile_path)
    decrypted = handler.decrypt_file(container, password, keyfile_path)
    return decrypted

class TestCorrectness:
    """Tests for correct encryption and decryption."""

    def test_correct_password_decrypts_successfully(self):
        """Correct password should decrypt successfully."""
        data = b"Hello, world!"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_correct_password_with_keyfile_decrypts_successfully(self):
        """Correct password and keyfile should decrypt successfully."""
        data = b"Hello, world!"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            keyfile.generate_keyfile(keyfile_path)
            container = handler.encrypt_file(data, password, keyfile_path)
            decrypted = handler.decrypt_file(container, password, keyfile_path)
            assert decrypted == data

    def test_round_trip_preserves_exact_bytes(self):
        """Encrypt then decrypt should yield identical bytes."""
        data = b"Binary data: \x00\x01\x02\xff\xfe"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_large_file_roundtrip(self):
        """A 5MB file should encrypt and decrypt correctly."""
        data = os.urandom(5 * 1024 * 1024)  # 5 MB
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_empty_file_roundtrip(self):
        """Empty file should encrypt and decrypt correctly."""
        data = b""
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

class TestNegative:
    """Tests that incorrect inputs should fail."""

    def test_wrong_password_fails(self):
        """Wrong password should raise ValueError."""
        data = b"secret"
        password = STRONG_PASSWORD
        wrong_password = STRONG_PASSWORD_2  # different strong password
        container = handler.encrypt_file(data, password)
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(container, wrong_password)

    def test_correct_password_keyfile_required_none_provided_fails(self):
        """If keyfile is required, providing none should fail."""
        data = b"secret"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            keyfile.generate_keyfile(keyfile_path)
            container = handler.encrypt_file(data, password, keyfile_path)
            # Now try to decrypt without keyfile
            with pytest.raises(ValueError, match="This file requires a key file"):
                handler.decrypt_file(container, password)

    def test_correct_password_wrong_keyfile_fails(self):
        """Correct password but wrong keyfile should fail."""
        data = b"secret"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path1 = os.path.join(tmpdir, "keyfile1")
            keyfile_path2 = os.path.join(tmpdir, "keyfile2")
            keyfile.generate_keyfile(keyfile_path1)
            keyfile.generate_keyfile(keyfile_path2)
            container = handler.encrypt_file(data, password, keyfile_path1)
            # Try to decrypt with the wrong keyfile
            with pytest.raises(ValueError, match="Wrong key file"):
                handler.decrypt_file(container, password, keyfile_path2)

    def test_empty_password_fails(self):
        """Empty password should raise ValueError during encryption."""
        data = b"secret"
        password = ""
        with pytest.raises(ValueError, match="Password must be at least 10 characters long"):
            handler.encrypt_file(data, password)

    def test_password_too_short_fails(self):
        """Password too short should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_SHORT
        with pytest.raises(ValueError, match="Password must be at least 10 characters long"):
            handler.encrypt_file(data, password)

    def test_password_no_uppercase_fails(self):
        """Password missing uppercase should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_UPPER
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            handler.encrypt_file(data, password)

    def test_password_no_lowercase_fails(self):
        """Password missing lowercase should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_LOWER
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            handler.encrypt_file(data, password)

    def test_password_no_digit_fails(self):
        """Password missing digit should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_DIGIT
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            handler.encrypt_file(data, password)

    def test_password_no_special_fails(self):
        """Password missing special character should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_SPECIAL
        with pytest.raises(ValueError, match="Password must contain at least one special character"):
            handler.encrypt_file(data, password)

    def test_long_password_works(self):
        """A 1000-character password that meets policy should work."""
        data = b"data"
        # Create a 1000-char string that meets the policy: repeat "Aa1!" 250 times
        password = "Aa1!" * 250  # 1000 chars, has upper, lower, digit, special
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_unicode_password_works(self):
        """Unicode password that meets policy should work."""
        data = b"data"
        # Unicode string with required character types, length >=10
        password = "🚀a1!🌟B2@" * 2  # length 24, contains emoji (Unicode), upper, lower, digit, special
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_special_character_password_works(self):
        """Password with special characters that meets policy should work."""
        data = b"data"
        # Start with specials and add required other types
        password = "Aa1!" + "!@#$%^&*()_+-=[]{}|;:,.<>?/"  # length >10, has upper, lower, digit, special
        # Ensure length >=10 (it is)
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

class TestCryptographicProperties:
    """Tests for cryptographic properties like non-determinism."""

    def test_two_encryptions_with_same_password_produce_different_ciphertext(self):
        """Same plaintext and password should yield different ciphertexts due to random salt/nonce."""
        data = b"identical"
        password = STRONG_PASSWORD
        container1 = handler.encrypt_file(data, password)
        container2 = handler.encrypt_file(data, password)
        # The containers should be different (different salt and nonce)
        assert container1 != container2
        # But both should decrypt to the same plaintext
        decrypted1 = handler.decrypt_file(container1, password)
        decrypted2 = handler.decrypt_file(container2, password)
        assert decrypted1 == decrypted2 == data

    def test_two_encryptions_produce_different_salts(self):
        """Two encryptions should have different salts."""
        data = b"data"
        password = STRONG_PASSWORD
        container1 = handler.encrypt_file(data, password)
        container2 = handler.encrypt_file(data, password)
        # Parse containers to get salt
        c1 = json.loads(container1.decode())
        c2 = json.loads(container2.decode())
        s1 = base64.b64decode(c1["salt"])
        s2 = base64.b64decode(c2["salt"])
        assert s1 != s2

    def test_two_encryptions_produce_different_nonces(self):
        """Two encryptions should have different nonces."""
        data = b"data"
        password = STRONG_PASSWORD
        container1 = handler.encrypt_file(data, password)
        container2 = handler.encrypt_file(data, password)
        c1 = json.loads(container1.decode())
        c2 = json.loads(container2.decode())
        n1 = base64.b64decode(c1["nonce"])
        n2 = base64.b64decode(c2["nonce"])
        assert n1 != n2

    def test_derived_key_is_always_32_bytes(self):
        """The derived key should always be 32 bytes."""
        password = STRONG_PASSWORD
        salt = os.urandom(config.ARGON2_SALT_LEN)
        key = kdf.derive_key(password, salt)
        assert len(key) == config.AES_KEY_LEN

class TestTamperDetection:
    """Tests that any tampering is detected."""

    def test_flip_one_bit_in_ciphertext(self):
        """Flipping a single bit in ciphertext should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        # Parse, flip a bit in ciphertext, re-encode
        c = json.loads(container.decode())
        # Decode ciphertext, flip first bit, re-encode
        ct = base64.b64decode(c["ciphertext"])
        # Flip the least significant bit of the first byte
        ct = bytes([ct[0] ^ 1]) + ct[1:]
        c["ciphertext"] = base64.b64encode(ct).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_replace_ciphertext_with_random_bytes(self):
        """Replacing ciphertext with random bytes should fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        # Replace with random bytes of same length
        ct = os.urandom(len(base64.b64decode(c["ciphertext"])))
        c["ciphertext"] = base64.b64encode(ct).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_modify_salt_in_container(self):
        """Modifying salt should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        # Change salt to something else
        c["salt"] = base64.b64encode(os.urandom(config.ARGON2_SALT_LEN)).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_modify_nonce_in_container(self):
        """Modifying nonce should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        c["nonce"] = base64.b64encode(os.urandom(config.AES_NONCE_LEN)).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_modify_tag_in_container(self):
        """Modifying tag should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        c["tag"] = base64.b64encode(os.urandom(16)).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_truncate_container_json(self):
        """Truncating the container JSON should cause a parse error."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        # Remove last character
        truncated = container[:-1]
        with pytest.raises(ValueError, match="Invalid container format"):
            handler.decrypt_file(truncated, password)

    def test_pass_random_bytes_as_container(self):
        """Passing random bytes as container should fail."""
        data = os.urandom(100)
        password = STRONG_PASSWORD
        with pytest.raises(ValueError, match="Invalid container format"):
            handler.decrypt_file(data, password)

    def test_pass_empty_byte_string_as_container(self):
        """Passing empty bytes as container should fail."""
        password = STRONG_PASSWORD
        with pytest.raises(ValueError, match="Invalid container format"):
            handler.decrypt_file(b"", password)

class TestKeyfile:
    """Tests for keyfile functionality."""

    def test_generate_keyfile_creates_correct_size(self):
        """Generated keyfile should be exactly KEYFILE_LEN bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            keyfile.generate_keyfile(path)
            with open(path, 'rb') as f:
                data = f.read()
            assert len(data) == config.KEYFILE_LEN

    def test_generate_keyfile_sets_permissions_to_0o600(self):
        """Generated keyfile should have permissions 0o600."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            keyfile.generate_keyfile(path)
            # Check permissions
            mode = os.stat(path).st_mode & 0o777
            assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_generate_keyfile_raises_if_file_exists(self):
        """Generating a keyfile should fail if file already exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            # Create the file first
            with open(path, 'wb') as f:
                f.write(b'0' * config.KEYFILE_LEN)
            # Now trying to generate should raise
            with pytest.raises(ValueError, match="Key file already exists"):
                keyfile.generate_keyfile(path)

    def test_load_keyfile_raises_if_file_missing(self):
        """Loading a non-existent keyfile should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            keyfile.load_keyfile("/non/existent/file")

    def test_load_keyfile_raises_if_file_wrong_size(self):
        """Loading a file of incorrect size should raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            with open(path, 'wb') as f:
                # Write wrong number of bytes
                f.write(b'0' * (config.KEYFILE_LEN - 1))
            with pytest.raises(ValueError, match=f"Key file must be {config.KEYFILE_LEN} bytes long"):
                keyfile.load_keyfile(path)

    def test_encrypt_with_keyfile_a_decrypt_with_keyfile_b_fails(self):
        """Encrypting with keyfile A and decrypting with keyfile B should fail."""
        data = b"secret"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_a = os.path.join(tmpdir, "keyfile_a")
            keyfile_b = os.path.join(tmpdir, "keyfile_b")
            keyfile.generate_keyfile(keyfile_a)
            keyfile.generate_keyfile(keyfile_b)
            container = handler.encrypt_file(data, password, keyfile_a)
            # Try to decrypt with keyfile B
            with pytest.raises(ValueError, match="Wrong key file"):
                handler.decrypt_file(container, password, keyfile_b)

    def test_keyfile_fingerprint_returns_64_char_hex(self):
        """Keyfile fingerprint should be a 64-character hex string."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            keyfile.generate_keyfile(path)
            with open(path, 'rb') as f:
                data = f.read()
            fingerprint = keyfile.keyfile_fingerprint(data)
            assert isinstance(fingerprint, str)
            assert len(fingerprint) == 64
            # Check that it's hexadecimal
            int(fingerprint, 16)  # Should not raise ValueError

    def test_container_stores_correct_fingerprint_for_keyfile_used(self):
        """The container should store the correct fingerprint for the keyfile used."""
        data = b"data"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            keyfile.generate_keyfile(keyfile_path)
            # Get the actual fingerprint of the keyfile
            with open(keyfile_path, 'rb') as f:
                keyfile_data = f.read()
            actual_fingerprint = keyfile.keyfile_fingerprint(keyfile_data)
            # Encrypt with keyfile
            container = handler.encrypt_file(data, password, keyfile_path)
            # Parse container and check fingerprint
            c = json.loads(container.decode())
            assert c["keyfile_fingerprint"] == actual_fingerprint
            assert c["keyfile_required"] is True

if __name__ == "__main__":
    pytest.main([__file__, "-v"])