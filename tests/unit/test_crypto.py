"""Unit tests for core/crypto.py."""

import tempfile
from pathlib import Path

import pytest

from netstego.core.crypto import (
    KEY_SIZE,
    decrypt,
    derive_key,
    encrypt,
    generate_key,
    load_key,
)


class TestKeyGeneration:
    def test_generate_key_creates_file(self, tmp_path: Path) -> None:
        key_path = tmp_path / "test.key"
        key = generate_key(key_path)
        assert key_path.exists()
        assert len(key) == KEY_SIZE
        assert key_path.read_bytes() == key

    def test_load_key_roundtrip(self, tmp_path: Path) -> None:
        key_path = tmp_path / "test.key"
        original = generate_key(key_path)
        loaded = load_key(key_path)
        assert original == loaded

    def test_load_key_wrong_size(self, tmp_path: Path) -> None:
        key_path = tmp_path / "bad.key"
        key_path.write_bytes(b"short")
        with pytest.raises(ValueError, match="must be 32 bytes"):
            load_key(key_path)


class TestDeriveKey:
    def test_derive_key_deterministic(self) -> None:
        password = b"test-password"
        key1, salt = derive_key(password)
        key2, _ = derive_key(password, salt)
        assert key1 == key2
        assert len(key1) == KEY_SIZE

    def test_derive_key_different_salts(self) -> None:
        password = b"test-password"
        key1, salt1 = derive_key(password)
        key2, salt2 = derive_key(password)
        assert salt1 != salt2
        assert key1 != key2


class TestEncryptDecrypt:
    def test_roundtrip_small(self) -> None:
        key = b"\x42" * KEY_SIZE
        plaintext = b"Hello, steganography!"
        ciphertext = encrypt(plaintext, key)
        result = decrypt(ciphertext, key)
        assert result == plaintext

    def test_roundtrip_empty(self) -> None:
        key = b"\x01" * KEY_SIZE
        plaintext = b""
        ciphertext = encrypt(plaintext, key)
        result = decrypt(ciphertext, key)
        assert result == plaintext

    def test_roundtrip_large(self) -> None:
        key = b"\xAB" * KEY_SIZE
        plaintext = b"\xDE\xAD" * 10000
        ciphertext = encrypt(plaintext, key)
        result = decrypt(ciphertext, key)
        assert result == plaintext

    def test_different_nonces(self) -> None:
        key = b"\x42" * KEY_SIZE
        plaintext = b"same data"
        c1 = encrypt(plaintext, key)
        c2 = encrypt(plaintext, key)
        assert c1 != c2  # different nonces

    def test_wrong_key_fails(self) -> None:
        key1 = b"\x01" * KEY_SIZE
        key2 = b"\x02" * KEY_SIZE
        ciphertext = encrypt(b"secret", key1)
        with pytest.raises(Exception):
            decrypt(ciphertext, key2)

    def test_tampered_ciphertext_fails(self) -> None:
        key = b"\x42" * KEY_SIZE
        ciphertext = bytearray(encrypt(b"data", key))
        ciphertext[-1] ^= 0xFF  # flip last byte
        with pytest.raises(Exception):
            decrypt(bytes(ciphertext), key)

    def test_too_short_data(self) -> None:
        key = b"\x42" * KEY_SIZE
        with pytest.raises(ValueError, match="too short"):
            decrypt(b"short", key)
