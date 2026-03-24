"""Cryptographic operations: AES-256-GCM encryption with Argon2id KDF.

References:
    - AES-GCM: NIST SP 800-38D
    - Argon2id: RFC 9106
"""

import secrets
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256 key size in bytes
KEY_SIZE = 32
# AES-GCM nonce size in bytes (96 bits as recommended by NIST)
NONCE_SIZE = 12
# Argon2id salt size
SALT_SIZE = 16


def generate_key(path: Path) -> bytes:
    """Generate a random 256-bit key and save to file.

    Args:
        path: File path to save the key.

    Returns:
        The generated key bytes.
    """
    key = secrets.token_bytes(KEY_SIZE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    return key


def load_key(path: Path) -> bytes:
    """Load a key from file.

    Args:
        path: File path to the key.

    Returns:
        The key bytes.

    Raises:
        ValueError: If key file has wrong size.
    """
    data = path.read_bytes()
    if len(data) != KEY_SIZE:
        msg = f"Key file must be {KEY_SIZE} bytes, got {len(data)}"
        raise ValueError(msg)
    return data


def derive_key(
    password: bytes,
    salt: bytes | None = None,
    *,
    time_cost: int = 3,
    memory_cost: int = 65536,
) -> tuple[bytes, bytes]:
    """Derive an AES-256 key from password using Argon2id.

    Args:
        password: Password or passphrase bytes.
        salt: Optional salt; generated randomly if not provided.
        time_cost: Argon2 time cost parameter.
        memory_cost: Argon2 memory cost in KiB.

    Returns:
        Tuple of (derived_key, salt).
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=1,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )
    return key, salt


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data with AES-256-GCM.

    Output format: nonce (12 bytes) || ciphertext || tag (16 bytes)

    Args:
        plaintext: Data to encrypt.
        key: 256-bit encryption key.

    Returns:
        Concatenated nonce + ciphertext + tag.
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM encrypted data.

    Expects format: nonce (12 bytes) || ciphertext || tag (16 bytes)

    Args:
        data: Encrypted data (nonce + ciphertext + tag).
        key: 256-bit encryption key.

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If data is too short to contain nonce + tag.
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    if len(data) < NONCE_SIZE + 16:
        msg = "Encrypted data too short"
        raise ValueError(msg)
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
