# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""In-process tests for the CLI, so that coverage can trace the cli module.

The existing subprocess-based CLI tests verify behavior end-to-end, but the
pytest-cov coverage tracer cannot follow code executed in subprocesses. These
tests call the cli functions directly (with GUN101_PASSWORD set) so that the
statement coverage of `cli.py` is measurable.
"""
import argparse
import contextlib
import io
import os
import sys

import pytest

from gun101 import cli, keyfile

STRONG_PASSWORD = "Str0ngP@ssw0rd!"


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run every test inside an isolated temp working directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def env_password(monkeypatch):
    monkeypatch.setenv("GUN101_PASSWORD", STRONG_PASSWORD)
    yield
    monkeypatch.delenv("GUN101_PASSWORD", raising=False)


def make_arg(**kwargs):
    return argparse.Namespace(**kwargs)


def run(func, args):
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            func(args)
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc


class TestEncryptInProcess:
    def test_encrypt_success(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"hello world")
        out, _, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output=None))
        assert exc is None
        assert "Encrypted file written to: in.txt.gun101" in out
        assert os.path.exists("in.txt.gun101")

    def test_encrypt_success_with_output(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"data")
        out, _, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.bin"))
        assert exc is None
        assert "out.bin" in out
        assert os.path.exists("out.bin")

    def test_encrypt_read_failure(self, workdir, env_password):
        _, err, exc = run(cli.encrypt, make_arg(file="missing.txt", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "Error reading file" in err

    def test_encrypt_weak_password_fails(self, workdir, monkeypatch):
        monkeypatch.setenv("GUN101_PASSWORD", "weak")
        with open("in.txt", "wb") as f:
            f.write(b"data")
        _, err, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "at least 10 characters" in err

    def test_encrypt_output_symlink_rejected(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"data")
        with open("target.bin", "wb") as f:
            f.write(b"x")
        os.symlink("target.bin", "link.bin")
        _, err, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output="link.bin"))
        assert exc is not None and exc.code == 1
        assert "symlink" in err

    def test_encrypt_output_escape_rejected(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"data")
        _, err, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output="../escape.bin"))
        assert exc is not None and exc.code == 1
        assert "escape" in err

    def test_encrypt_keyfile_roundtrip(self, workdir, env_password):
        keyfile.generate_keyfile("kf")
        with open("in.txt", "wb") as f:
            f.write(b"secret")
        out, _, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile="kf", output=None))
        assert exc is None
        assert "in.txt.gun101" in out
        out, _, exc = run(cli.decrypt, make_arg(file="in.txt.gun101", keyfile="kf", output="out.txt"))
        assert exc is None
        with open("out.txt", "rb") as f:
            assert f.read() == b"secret"


class TestDecryptInProcess:
    def _encrypt(self, name="todo.txt"):
        with open(name, "wb") as f:
            f.write(b"payload")
        run(cli.encrypt, make_arg(file=name, keyfile=None, output=None))
        return name + ".gun101"

    def test_decrypt_success(self, workdir, env_password):
        enc = self._encrypt()
        out, _, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="restored.txt"))
        assert exc is None
        assert "restored.txt" in out
        with open("restored.txt", "rb") as f:
            assert f.read() == b"payload"

    def test_decrypt_default_extension(self, workdir, env_password):
        enc = self._encrypt()
        out, _, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output=None))
        assert exc is None
        assert "todo.txt" in out
        assert os.path.exists("todo.txt")

    def test_decrypt_default_decrypted_suffix(self, workdir, env_password):
        with open("data.bin", "wb") as f:
            f.write(b"payload")
        run(cli.encrypt, make_arg(file="data.bin", keyfile=None, output=None))
        os.rename("data.bin.gun101", "container.custom")
        out, _, exc = run(cli.decrypt, make_arg(file="container.custom", keyfile=None, output=None))
        assert exc is None
        assert "container.custom.decrypted" in out
        assert os.path.exists("container.custom.decrypted")

    def test_decrypt_wrong_password_fails(self, workdir, env_password, monkeypatch):
        enc = self._encrypt()
        monkeypatch.setenv("GUN101_PASSWORD", "Different1!Pass")
        _, err, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="x.txt"))
        assert exc is not None and exc.code == 1
        assert "Decryption failed" in err

    def test_decrypt_read_failure(self, workdir, env_password):
        _, err, exc = run(cli.decrypt, make_arg(file="missing.gun101", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "Error reading file" in err

    def test_decrypt_output_symlink_rejected(self, workdir, env_password):
        enc = self._encrypt()
        with open("t.bin", "wb") as f:
            f.write(b"x")
        os.symlink("t.bin", "link.bin")
        _, err, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="link.bin"))
        assert exc is not None and exc.code == 1
        assert "symlink" in err

    def test_decrypt_output_escape_rejected(self, workdir, env_password):
        enc = self._encrypt()
        _, err, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="../escape.txt"))
        assert exc is not None and exc.code == 1
        assert "escape" in err


class TestGenerateKeyfileInProcess:
    def test_generate_success(self, workdir):
        out, _, exc = run(cli.generate_keyfile, make_arg(path="kf"))
        assert exc is None
        assert "Keyfile generated at: kf" in out
        assert "Fingerprint (SHA-256):" in out
        assert os.path.exists("kf")

    def test_generate_existing_fails(self, workdir):
        with open("kf", "wb") as f:
            f.write(b"0" * 32)
        _, err, exc = run(cli.generate_keyfile, make_arg(path="kf"))
        assert exc is not None and exc.code == 1
        assert "already exists" in err

    def test_generate_symlink_rejected(self, workdir):
        os.symlink("nonexistent-target", "link")
        _, err, exc = run(cli.generate_keyfile, make_arg(path="link"))
        assert exc is not None and exc.code == 1
        assert "symlink" in err

    def test_generate_escape_rejected(self, workdir):
        _, err, exc = run(cli.generate_keyfile, make_arg(path="../outside.kf"))
        assert exc is not None and exc.code == 1
        assert "escape" in err


class TestKeyfileFingerprintInProcess:
    def test_fingerprint_success(self, workdir):
        keyfile.generate_keyfile("kf")
        out, _, exc = run(cli.keyfile_fingerprint, make_arg(path="kf"))
        assert exc is None
        assert "Fingerprint (SHA-256):" in out

    def test_fingerprint_missing_file_fails(self, workdir):
        _, err, exc = run(cli.keyfile_fingerprint, make_arg(path="nope"))
        assert exc is not None and exc.code == 1
        assert "Error reading keyfile" in err

    def test_fingerprint_wrong_size_fails(self, workdir):
        with open("kf", "wb") as f:
            f.write(b"short")
        _, err, exc = run(cli.keyfile_fingerprint, make_arg(path="kf"))
        assert exc is not None and exc.code == 1
        assert "Error:" in err


class TestInfoInProcess:
    def test_info_success(self):
        out, err, exc = run(cli.info, make_arg())
        assert exc is None
        assert err == ""
        lines = dict(line.split("=", 1) for line in out.strip().splitlines())
        assert lines["protocol"] == "GUN-101"
        assert lines["container_version"] == "2.1"
        assert lines["argon2_time_cost"] == "4"
        assert lines["argon2_memory_cost"] == "262144"
        assert lines["argon2_parallelism"] == "4"
        assert lines["argon2_hash_len"] == "32"
        assert lines["argon2_salt_len"] == "32"
        assert lines["cryptography_version"] != ""
        assert lines["argon2_cffi_version"] != ""
        assert lines["password_min_length"] == "10"
        assert lines["password_require_uppercase"] == "true"
        assert lines["password_require_lowercase"] == "true"
        assert lines["password_require_digit"] == "true"
        assert lines["password_require_special"] == "true"
        assert "password_policy" in lines

    def test_info_unknown_dependency_fallback(self, monkeypatch):
        import importlib.metadata

        def mock_version(pkg_name):
            raise importlib.metadata.PackageNotFoundError(pkg_name)

        monkeypatch.setattr(importlib.metadata, "version", mock_version)
        out, err, exc = run(cli.info, make_arg())
        assert exc is None
        assert err == ""
        lines = dict(line.split("=", 1) for line in out.strip().splitlines())
        assert lines["cryptography_version"] == "unknown"
        assert lines["argon2_cffi_version"] == "unknown"


def run_main():
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main()
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc


class TestMainDispatchInProcess:
    """Exercise main() and the argparse wiring so it is coverage-traceable."""

    def test_main_info(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["gun101", "info"])
        out, err, exc = run_main()
        assert exc is None
        assert err == ""
        assert "protocol=GUN-101" in out
        assert "container_version=2.1" in out
        assert "cryptography_version=" in out
        assert "argon2_cffi_version=" in out

    def test_main_encrypt(self, workdir, env_password, monkeypatch):
        with open("in.txt", "wb") as f:
            f.write(b"hello")
        monkeypatch.setattr(sys, "argv", ["gun101", "encrypt", "in.txt"])
        out, err, exc = run_main()
        assert exc is None
        assert os.path.exists("in.txt.gun101")

    def test_main_decrypt(self, workdir, env_password, monkeypatch):
        with open("in.txt", "wb") as f:
            f.write(b"payload")
        monkeypatch.setattr(sys, "argv", ["gun101", "encrypt", "in.txt"])
        run_main()
        monkeypatch.setattr(sys, "argv", ["gun101", "decrypt", "in.txt.gun101", "--output", "out.txt"])
        out, err, exc = run_main()
        assert exc is None
        with open("out.txt", "rb") as f:
            assert f.read() == b"payload"

    def test_main_generate_keyfile(self, workdir, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["gun101", "generate-keyfile", "my.kf"])
        out, err, exc = run_main()
        assert exc is None
        assert os.path.exists("my.kf")

    def test_main_keyfile_fingerprint(self, workdir, monkeypatch):
        keyfile.generate_keyfile("my.kf")
        monkeypatch.setattr(sys, "argv", ["gun101", "keyfile-fingerprint", "my.kf"])
        out, err, exc = run_main()
        assert exc is None
        assert "Fingerprint (SHA-256):" in out

    def test_main_unknown_subcommand(self, workdir, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["gun101", "frobnicate"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2

    def test_main_encrypt_with_keyfile(self, workdir, env_password, monkeypatch):
        keyfile.generate_keyfile("kf")
        with open("in.txt", "wb") as f:
            f.write(b"secret")
        monkeypatch.setattr(
            sys, "argv", ["gun101", "encrypt", "in.txt", "--keyfile", "kf"])
        out, err, exc = run_main()
        assert exc is None
        monkeypatch.setattr(
            sys, "argv", ["gun101", "decrypt", "in.txt.gun101", "--keyfile", "kf", "--output", "out.txt"])
        out, err, exc = run_main()
        assert exc is None
        with open("out.txt", "rb") as f:
            assert f.read() == b"secret"


class TestGetPasswordPathInProcess:
    def test_prompts_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("GUN101_PASSWORD", raising=False)
        monkeypatch.setattr("getpass.getpass", lambda prompt="Password: ": "M0nkeyP@ss!")
        password = cli.get_password()
        assert password == "M0nkeyP@ss!"

    def test_generate_keyfile_oserror_branch(self, workdir):
        with open("afile", "wb") as f:
            f.write(b"x")
        _, err, exc = run(cli.generate_keyfile, make_arg(path="afile/inner.kf"))
        assert exc is not None and exc.code == 1
        assert "Error creating keyfile" in err
