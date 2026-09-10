# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Property-based fuzz tests for decrypt_file's container parser and field-decode stage."""
from __future__ import annotations

import base64
import json
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gun101 import config, handler, keyfile

PASSWORD = "P" * 4 + "a" * 4 + "1" * 4 + "!"
DUMMY_KEYFILE_PATH = "tmp_fuzz_dummy_keyfile.bin"


@pytest.fixture(autouse=True, scope="module")
def setup_fuzz_environment():
    """Configure fast KDF parameters and temporary keyfile for parser fuzzing."""
    orig_mem = config.ARGON2_MEMORY_COST
    orig_time = config.ARGON2_TIME_COST
    orig_par = config.ARGON2_PARALLELISM

    config.ARGON2_MEMORY_COST = 8
    config.ARGON2_TIME_COST = 1
    config.ARGON2_PARALLELISM = 1

    # Create dummy keyfile for keyfile fingerprint tests
    with open(DUMMY_KEYFILE_PATH, "wb") as f:
        f.write(b"k" * config.KEYFILE_LEN)

    yield

    # Restore production config
    config.ARGON2_MEMORY_COST = orig_mem
    config.ARGON2_TIME_COST = orig_time
    config.ARGON2_PARALLELISM = orig_par

    if os.path.exists(DUMMY_KEYFILE_PATH):
        os.unlink(DUMMY_KEYFILE_PATH)


def make_valid_container() -> dict:
    """Return a structurally valid container dictionary."""
    return {
        "protocol": config.PROTOCOL,
        "version": "2.1",
        "keyfile_required": False,
        "keyfile_fingerprint": None,
        "salt": base64.b64encode(b"s" * config.ARGON2_SALT_LEN).decode("utf-8"),
        "nonce": base64.b64encode(b"n" * config.AES_NONCE_LEN).decode("utf-8"),
        "ciphertext": base64.b64encode(b"c" * 32).decode("utf-8"),
        "tag": base64.b64encode(b"t" * 16).decode("utf-8"),
    }


@settings(max_examples=50, deadline=None)
@given(st.binary(max_size=256))
def test_fuzz_malformed_json_bytes(data: bytes):
    """Raw arbitrary bytes must raise ValueError('Decryption failed')."""
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(data, PASSWORD)


@settings(max_examples=50, deadline=None)
@given(st.text(max_size=256).filter(lambda s: not s.strip().startswith("{")))
def test_fuzz_malformed_json_text(text: str):
    """Malformed JSON text must raise ValueError('Decryption failed')."""
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(text.encode("utf-8", errors="replace"), PASSWORD)


@settings(max_examples=30, deadline=None)
@given(st.one_of(st.text(max_size=50), st.integers(), st.none(), st.lists(st.integers(), max_size=3)))
def test_fuzz_non_bytes_container_data(bad_input):
    """Non-bytes container_data inputs must raise ValueError('Decryption failed')."""
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(bad_input, PASSWORD)


@settings(max_examples=50, deadline=None)
@given(
    st.one_of(
        st.integers(),
        st.floats(allow_nan=False),
        st.text(max_size=50),
        st.booleans(),
        st.none(),
        st.lists(st.integers(), max_size=5),
    )
)
def test_fuzz_non_dict_container_roots(val):
    """Non-dict JSON roots (int, list, str, bool, null) must raise ValueError('Decryption failed')."""
    payload = json.dumps(val).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD)


@settings(max_examples=50, deadline=None)
@given(
    st.one_of(
        st.text(max_size=30).filter(lambda s: s != config.PROTOCOL),
        st.integers(),
        st.none(),
        st.booleans(),
        st.lists(st.text(max_size=5), max_size=2),
    )
)
def test_fuzz_protocol_validation(bad_protocol):
    """Invalid or non-matching protocol must raise ValueError('Decryption failed')."""
    container = make_valid_container()
    container["protocol"] = bad_protocol
    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD)


@settings(max_examples=50, deadline=None)
@given(
    st.one_of(
        st.text(max_size=20).filter(lambda s: s not in ("2.0", "2.1")),
        st.integers(),
        st.none(),
        st.booleans(),
        st.lists(st.text(max_size=5), max_size=2),
    )
)
def test_fuzz_version_validation(bad_version):
    """Unsupported version values or types must raise ValueError('Decryption failed')."""
    container = make_valid_container()
    container["version"] = bad_version
    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD)


@settings(max_examples=30, deadline=None)
@given(st.one_of(st.just(True), st.text(min_size=1, max_size=10), st.integers(min_value=1, max_value=100)))
def test_fuzz_keyfile_required_without_keyfile(kf_val):
    """Containers requiring keyfile without providing one must raise ValueError('Decryption failed')."""
    container = make_valid_container()
    container["keyfile_required"] = kf_val
    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD, keyfile_path=None)


@settings(max_examples=50, deadline=None)
@given(
    st.one_of(
        st.none(),
        st.text(max_size=64).filter(
            lambda s: s != keyfile.keyfile_fingerprint(b"k" * config.KEYFILE_LEN)
        ),
        st.integers(),
        st.booleans(),
        st.lists(st.text(max_size=5), max_size=2),
        st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=2),
    )
)
def test_fuzz_keyfile_fingerprint_handling(bad_fingerprint):
    """Mismatched, missing, or malformed fingerprint types must raise ValueError('Decryption failed')."""
    container = make_valid_container()
    container["keyfile_required"] = True
    container["keyfile_fingerprint"] = bad_fingerprint
    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD, keyfile_path=DUMMY_KEYFILE_PATH)


bad_base64_or_types = st.one_of(
    st.sampled_from(["A==", "AAA", "A===", "AAAAA", "invalid base64!"]),
    st.integers(),
    st.none(),
    st.booleans(),
    st.lists(st.text(max_size=5), max_size=2),
    st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=2),
)


@pytest.mark.parametrize("field", ["salt", "nonce", "ciphertext", "tag"])
@settings(max_examples=30, deadline=None)
@given(bad_base64_or_types)
def test_fuzz_crypto_field_base64_decode_errors(field: str, bad_val):
    """Malformed base64 or unexpected types for crypto fields must raise ValueError('Decryption failed')."""
    container = make_valid_container()
    container[field] = bad_val
    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD)


@pytest.mark.parametrize("field", ["protocol", "version", "salt", "nonce", "ciphertext", "tag"])
def test_missing_required_fields(field: str):
    """Missing any required container field must raise ValueError('Decryption failed')."""
    container = make_valid_container()
    del container[field]
    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD)


field_name_strat = st.sampled_from(
    ["protocol", "version", "keyfile_required", "keyfile_fingerprint", "salt", "nonce", "ciphertext", "tag"]
)
mutation_op = st.sampled_from(
    ["drop", "int", "none", "bool", "list", "corrupt_b64"]
)


@settings(max_examples=100, deadline=None)
@given(st.lists(st.tuples(field_name_strat, mutation_op), min_size=1, max_size=5))
def test_fuzz_random_mutations_never_raise_unexpected(mutations):
    """Randomly mutated containers must raise ValueError('Decryption failed') or ValueError."""
    container = make_valid_container()
    for field, op in mutations:
        if op == "drop":
            container.pop(field, None)
        elif op == "int":
            container[field] = 12345
        elif op == "none":
            container[field] = None
        elif op == "bool":
            container[field] = True
        elif op == "list":
            container[field] = [1, 2, "bad"]
        elif op == "corrupt_b64":
            container[field] = "A=="

    payload = json.dumps(container).encode("utf-8")
    with pytest.raises(ValueError, match="^Decryption failed$"):
        handler.decrypt_file(payload, PASSWORD)
